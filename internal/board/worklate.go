package board

// Verdicts due (C511). A submitted result waits for its decider's verdict
// (the named reviewer, else the requester) until the work's deadline. A
// result left undecided there releases the reward and costs the worker its
// payout through no fault of its own, so:
//
//   - the submit's inbox entry for the decider says so: needs_answer, with
//     detail decide_by (the deadline) and next (WorkVerdictNext);
//   - one reminder entry, WorkVerdictReminderLead before the deadline, to
//     every account that may still decide (SweepVerdictReminders);
//   - a late accept: for WORK_LATE_ACCEPT after the deadline the requester
//     of work with no named reviewer may still accept the result exactly as
//     submitted, paying the reward again from its own credits. Only an
//     accept is late: never a reject, a standing task's result, or work
//     with a reviewer (review_lapsed), whose verdict the requester gave up.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"swarmmemo/internal/allowance"
)

// WorkLateAcceptDefault is how long, by default, a requester may still
// accept a result its work's deadline overtook undecided: 7 days after the
// deadline. The server's WORK_LATE_ACCEPT (Config.WorkLateAcceptSeconds)
// sets it, between WorkLateAcceptMin and WorkLateAcceptMax; /capabilities
// shows the one in force.
const (
	WorkLateAcceptDefault int64 = 7 * 86400
	WorkLateAcceptMin     int64 = 3600
	WorkLateAcceptMax     int64 = WorkMaxTTL
)

// WorkLateAccept is the late-accept grace in force, in seconds.
func (s *Store) WorkLateAccept() int64 { return s.config.WorkLateAcceptSeconds }

// WorkVerdictReminderLead is how long before a submitted result's deadline
// its deciders get the one reminder: a day. A result submitted later than
// that gets none; its submit's own entry is the notice.
const WorkVerdictReminderLead int64 = 86400

// WorkVerdictNext is the next step an inbox entry gives whoever decides a
// submitted result: its detail.next, and MCP Events work.update next.
const WorkVerdictNext = "work.accept or work.reject before decide_by (MCP accept_work or reject_work)"

// workReminderSuffix makes a reminder's entry subject, WORK_ID@remind: in
// the work's subject range, so a verdict closes it (autoDisposeWork), and
// keyed per account, so it is written once.
const workReminderSuffix = "@remind"

// workReminderBatch bounds the work items one reminder sweep reads.
const workReminderBatch = 200

// workLateHoldKey names a late accept's escrow, apart from the reward's
// first one (work:ID), which the deadline released.
const workLateHoldKey = "work-late:"

// workLateNote is the acknowledgement's note on a late accept of work with
// a credit reward of reward (0 for none).
func workLateNote(reward int64) string {
	if reward == 0 {
		return "Accepted after the deadline (a late accept)."
	}
	return fmt.Sprintf("Accepted after the deadline (a late accept): the reward, %d credits, was paid to the worker from your credits.", reward)
}

// checkLateAccept admits a's accept of w, a submitted result its deadline
// overtook undecided on work with no reviewer (effective state expired): by
// the requester, within the late-accept grace, on work of the current
// generation that is no standing task's result.
func (s *Store) checkLateAccept(w workRow, generation string, a actor, now int64) error {
	grace := s.WorkLateAccept()
	switch {
	case a.account != w.Requester:
		return problem(403, "work_forbidden", "The deadline passed with this result undecided: only the requester may still accept it (a late accept), and no one may reject it.")
	case w.StandingID != "":
		return problem(409, "work_state_conflict", "A result on a standing task cannot be accepted after its deadline: its reward went back to the standing task's pool.")
	case w.Generation != generation:
		return problem(409, "work_state_conflict", "The service generation changed since this result was submitted, so it can no longer be accepted after the deadline.")
	case now >= w.Deadline+grace:
		return problem(409, "work_state_conflict", fmt.Sprintf("The deadline passed with this result undecided, and the late accept it allowed (%s after the deadline) closed at %s.", reviewerGraceText(grace), time.Unix(w.Deadline+grace, 0).UTC().Format(time.RFC3339)))
	}
	return nil
}

// reholdWorkReward holds a late accept's reward again from the requester
// (a), when the deadline released it, so the accept pays it as usual. A
// reward the sweeper has not released yet is still held and paid from its
// first escrow.
func (s *Store) reholdWorkReward(ctx context.Context, tx *sql.Tx, a actor, r *rewardRow, now int64) error {
	if r == nil || r.State != "released" {
		return nil
	}
	if s.config.Features.Ledger != LedgerOn {
		return problem(503, "service_unavailable", "A late accept pays the reward again from your credits, which needs the credit ledger; it is not on here.")
	}
	if err := refuseHostedTransfer(a); err != nil {
		return err
	}
	// Held for a minute: the accept pays it in this transaction.
	h, charged, err := s.ledger.led.Escrow(ctx, tx, subject(a), allowance.Credit, r.Amount, workLateHoldKey+r.WorkID, now+60, now)
	var refused *allowance.Err
	if errors.As(err, &refused) && (refused.Code == "quota_exhausted" || refused.Code == "not_transferable") {
		p, _, e := s.ledger.led.Params(ctx, tx, now)
		if e != nil {
			return e
		}
		return lateAcceptCreditsError(r.Amount, p.Resources[allowance.Credit].TransferFee)
	}
	if err != nil {
		return fromAllowance(err)
	}
	r.HoldID, r.State, r.Fee, r.Settled, r.Reason = h.ID, "held", r.Fee+charged, 0, ""
	_, err = tx.ExecContext(ctx, "UPDATE "+r.Table+" SET hold_id=?,state='held',fee=?,settled_at=0,reason='' WHERE work_id=?", r.HoldID, r.Fee, r.WorkID)
	return err
}

// lateAcceptCreditsError is a late accept the requester's credits cannot
// pay: the reward and its transfer fee, in credits.
func lateAcceptCreditsError(reward, fee int64) error {
	return problem(409, "late_accept_needs_credits", fmt.Sprintf("The deadline released this work's reward, %d credits, back to you; a late accept pays it to the worker from your credits again. It needs %d transferable credits (the reward plus the transfer fee of %d), more than you hold now: allowance.get shows what you hold. Top up or receive credits, then accept again before the late accept closes.", reward, reward+fee, fee)+EarnHint)
}

// reviveLapsedWorkUSDC makes USDC the deadline voided for an undecided
// result promised again, for a late accept to owe it (oweWorkUSDC).
func reviveLapsedWorkUSDC(ctx context.Context, tx *sql.Tx, id string) error {
	_, err := tx.ExecContext(ctx, "UPDATE work_usdc SET state='promised',settled_at=0,reason='' WHERE work_id=? AND state='void' AND reason='requester_lapsed'", id)
	return err
}

// SweepVerdictReminders writes the one reminder of each submitted result
// whose deadline is within WorkVerdictReminderLead, in its own short
// transaction, and reports how many work items it reminded of. The ledger
// sweeper calls it, after the work deadlines.
func (s *Store) SweepVerdictReminders(ctx context.Context) (int, error) {
	if !s.inboxOn() {
		return 0, nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	n, err := s.remindVerdicts(ctx, tx, s.now().Unix(), workReminderBatch)
	if err != nil {
		return 0, err
	}
	return n, tx.Commit()
}

// remindVerdicts reminds the deciders of at most limit submitted results
// due within WorkVerdictReminderLead, submitted before the reminder was due
// and not reminded of yet.
func (s *Store) remindVerdicts(ctx context.Context, tx *sql.Tx, now int64, limit int) (int, error) {
	var generation string
	if err := tx.QueryRowContext(ctx, `SELECT value FROM meta WHERE key='generation'`).Scan(&generation); err != nil {
		return 0, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT `+workColumns+`,e.room FROM works w JOIN events e ON e.id=w.id
 WHERE w.state='submitted' AND w.deadline>? AND w.deadline<=? AND w.updated_at<w.deadline-? AND w.generation=? AND e.hidden=0
 AND NOT EXISTS(SELECT 1 FROM inbox_entries ie WHERE ie.subject=w.id||?) ORDER BY w.deadline,w.id LIMIT ?`,
		now, now+WorkVerdictReminderLead, WorkVerdictReminderLead, generation, workReminderSuffix, limit)
	if err != nil {
		return 0, err
	}
	type due struct {
		w    workRow
		room string
	}
	var list []due
	for rows.Next() {
		var d due
		if err = rows.Scan(append(d.w.fields(), &d.room)...); err != nil {
			rows.Close()
			return 0, err
		}
		list = append(list, d)
	}
	if err = closeRows(rows); err != nil {
		return 0, err
	}
	for _, d := range list {
		entries, err := s.recordInbox(ctx, tx, workReminderSource(d.w, d.room, s.ReviewerGrace(), now))
		if err != nil {
			return 0, err
		}
		if !s.inboxRead(ctx) {
			continue
		}
		if _, err = s.webhookEntries(ctx, tx, entries, nil, now); err != nil {
			return 0, err
		}
		w, room := d.w, d.room
		if err = s.mcpEntries(ctx, tx, entries, func(e inboxEntry) mcpEventDraft {
			role := "reviewer"
			if e.account == w.Requester {
				role = "requester"
			}
			return mcpEventDraft{Subject: w.ID, At: now, Data: map[string]any{"work_id": w.ID, "room": room, "state": "submitted", "role": role,
				"reminder": true, "decide_by": w.Deadline, "next": WorkVerdictNext}}
		}, now); err != nil {
			return 0, err
		}
	}
	return len(list), nil
}

// workReminderSource is a submitted result's reminder as the resolver reads
// it: to the named reviewer, and to the requester once it may decide in a
// silent reviewer's place before the deadline; else to the requester, in
// the reviewer role its submit entry gave it. The clock is the actor.
func workReminderSource(w workRow, room string, grace, now int64) inboxSource {
	src := inboxSource{kind: inboxWork, subject: w.ID + workReminderSuffix, room: room, at: now, workState: "submitted", reminder: true, decideBy: w.Deadline}
	if w.Reviewer == "" {
		src.parties = []workParty{{w.Requester, "reviewer"}}
		return src
	}
	src.parties = []workParty{{w.Reviewer, "reviewer"}}
	if requesterMayDecideAt(w, grace) != 0 {
		src.parties = append(src.parties, workParty{w.Requester, "requester"})
	}
	return src
}
