package board

import (
	"cmp"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"swarmmemo/internal/reviews"
	"swarmmemo/internal/services"
)

// Prompts to rate after a real transaction (C306, RFC 0020 §9: thin
// markets pay nothing; the fix is more judges per subject). They are tips
// of the one engine (nudges.go), rows of NudgeCodes with Feature reviews:
//
//   - rate_paid_call: a signed caller whose paid call finished (an
//     offering call answered, a relayed x402 call done at a cost, or a call
//     of one of SwarmMemo's own tools that spent paid or earned credit, C301)
//     and who has not reviewed what it paid for; how cites call:ID.
//   - rate_worker: a requester with a submitted result waiting, who has not
//     reviewed the worker; how is the rated accept.
//
// Each pair (the counterparty and the subject) is prompted once per
// subject, ever: the pair is logged in the row's variant ("0|PAIR") and a
// pair already logged, shown or held out, is never offered again. Neither
// is a pair where either side is on the funnel exclude list (the
// operator's own personas). The caps, the holdout, nudges off and the
// openai suppression are the engine's.

const (
	// rateLookbackSeconds is how far back a paid call or a waiting result
	// is still worth a prompt.
	rateLookbackSeconds = 7 * 86400
	// rateCandidates bounds the transactions one answer considers.
	rateCandidates = 8
	// rateWhatBytes bounds the name of what was paid for in a tip's text.
	rateWhatBytes = 36
)

// rateCodes are the catalogue's rating prompts: the loop panel's nudges
// (FunnelLoop).
func rateCodes() []string {
	var out []string
	for _, n := range NudgeCodes {
		if n.Kind == NudgeTip && n.Feature == "reviews" {
			out = append(out, n.Code)
		}
	}
	return out
}

// rateCandidate is one transaction a prompt may name.
type rateCandidate struct {
	pair string // counterparty/subject id: prompted once
	vars map[string]string
}

// nudgePairVar is the fact var that carries a tip's pair to its log row.
const nudgePairVar = "_pair"

// pairVariant is a log row's variant with its pair.
func pairVariant(variant, pair string) string {
	if pair == "" {
		return variant
	}
	return variant + "|" + pair
}

// ratePrompted reports whether code was already logged for pair to the
// subject (flushed or still held).
func (s *Store) ratePrompted(ctx context.Context, key, code, pair string) (bool, error) {
	f := &s.funnel
	f.mu.Lock()
	for _, n := range f.nudges {
		if n.subject == key && n.code == code && strings.HasSuffix(n.variant, "|"+pair) {
			f.mu.Unlock()
			return true, nil
		}
	}
	f.mu.Unlock()
	var n int
	err := s.db.QueryRowContext(ctx, "SELECT count(*) FROM nudge_events WHERE subject=? AND code=? AND substr(variant,instr(variant,'|')+1)=?", key, code, pair).Scan(&n)
	return n > 0, err
}

// rateFirst is the first candidate whose pair was never prompted and whose
// counterparty is not excluded.
func (s *Store) rateFirst(ctx context.Context, c *nudgeCall, code string, cands []rateCandidate, excluded map[string]bool) (map[string]string, bool) {
	for _, cand := range cands {
		counterparty, _, _ := strings.Cut(cand.pair, "/")
		if excluded[counterparty] {
			continue
		}
		done, err := s.ratePrompted(ctx, c.sub.account, code, cand.pair)
		if err != nil {
			return nil, false
		}
		if !done {
			cand.vars[nudgePairVar] = cand.pair
			return cand.vars, true
		}
	}
	return nil, false
}

// rateSubjectOK is the common gate: a signed account not on the exclude
// list. It returns the list for the counterparty check.
func (s *Store) rateSubjectOK(ctx context.Context, c *nudgeCall) (map[string]bool, bool) {
	if !c.signed || c.sub.account == "" {
		return nil, false
	}
	excluded, err := s.funnelExcluded(ctx)
	if err != nil || excluded[c.sub.account] {
		return nil, false
	}
	return excluded, true
}

// ratePaidCallFact is rate_paid_call's when: the caller's paid calls that
// finished within the lookback, the one this answer is about first, that
// it has not reviewed.
func (s *Store) ratePaidCallFact(ctx context.Context, c *nudgeCall) (map[string]string, bool) {
	excluded, ok := s.rateSubjectOK(ctx, c)
	if !ok {
		return nil, false
	}
	// Elsewhere than on the call's own answer, only an account that has
	// paid for a call is looked up.
	switch c.cmd.Operation {
	case "home":
		if c.sub.acts&ActBit("paid_call") == 0 {
			return nil, false
		}
	case "service.call":
		// Only the relay's own answer, or a tool's (directly or through
		// tools.call).
		e := s.services.engine
		if c.cmd.Target != "x402" && (e == nil || c.cmd.Target != services.ToolsID && !e.Registry().HasTools(c.cmd.Target)) {
			return nil, false
		}
	}
	var cands []rateCandidate
	err := s.publicRead(ctx, func(ctx context.Context, tx *sql.Tx) error {
		var err error
		cands, err = s.paidCallsToRate(ctx, tx, c.sub.account, c.now)
		return err
	})
	if err != nil || len(cands) == 0 {
		return nil, false
	}
	if c.cmd.Operation == "offering.call.get" {
		for i, cand := range cands {
			if cand.vars["call"] == c.cmd.Target {
				cands[0], cands[i] = cands[i], cands[0]
				break
			}
		}
	}
	return s.rateFirst(ctx, c, "rate_paid_call", cands, excluded)
}

// paidCallsToRate are account's finished paid calls within the lookback,
// newest first, whose subject it has not reviewed: offering calls it
// signed that were answered, relayed x402 calls done at a cost, and calls
// of SwarmMemo's own tools that spent paid or earned credit (callPaid, the
// call evidence's own test: the review it prompts verifies as paid use).
func (s *Store) paidCallsToRate(ctx context.Context, tx *sql.Tx, account string, now int64) ([]rateCandidate, error) {
	since := now - rateLookbackSeconds
	type paid struct {
		id, seller, name, public string
		tool                     reviews.Subject // a call of one of our tools
		at                       int64
	}
	var calls []paid
	rows, err := tx.QueryContext(ctx, `SELECT id,account,name,answered_at FROM offering_calls
 WHERE caller<>'' AND caller IN (SELECT id FROM identities WHERE account=?) AND state='answered' AND answered_at>?
 ORDER BY answered_at DESC LIMIT ?`, account, since, rateCandidates)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var p paid
		if err = rows.Scan(&p.id, &p.seller, &p.name, &p.at); err != nil {
			rows.Close()
			return nil, err
		}
		calls = append(calls, p)
	}
	if err = rows.Close(); err != nil {
		return nil, err
	}
	rows, err = tx.QueryContext(ctx, `SELECT id,public,coalesce(nullif(finished_at,0),created_at) FROM service_calls
 WHERE account=? AND created_at>? AND service='x402' AND state='done' AND cost>0 ORDER BY created_at DESC LIMIT ?`, account, since, rateCandidates)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var p paid
		if err = rows.Scan(&p.id, &p.public, &p.at); err != nil {
			rows.Close()
			return nil, err
		}
		calls = append(calls, p)
	}
	if err = rows.Close(); err != nil {
		return nil, err
	}
	if e := s.services.engine; e != nil {
		rows, err = tx.QueryContext(ctx, `SELECT id,service,method,hold_id,coalesce(nullif(finished_at,0),created_at) FROM service_calls
 WHERE account=? AND created_at>? AND service NOT IN ('x402',?) AND state='done' AND cost>0 ORDER BY created_at DESC LIMIT ?`, account, since, services.ToolsID, rateCandidates)
		if err != nil {
			return nil, err
		}
		type toolCall struct {
			p                     paid
			service, method, hold string
		}
		var tcs []toolCall
		for rows.Next() {
			var t toolCall
			if err = rows.Scan(&t.p.id, &t.service, &t.method, &t.hold, &t.p.at); err != nil {
				rows.Close()
				return nil, err
			}
			tcs = append(tcs, t)
		}
		if err = rows.Close(); err != nil {
			return nil, err
		}
		for _, t := range tcs {
			if !e.Registry().IsTool(t.service, t.method) {
				continue
			}
			if t.p.tool, err = reviews.Canonical(reviews.TypeTool, services.ToolID(t.service, t.method), reviews.Options{}); err != nil {
				continue
			}
			ok, err := callPaid(ctx, tx, account, t.hold)
			if err != nil {
				return nil, err
			}
			if ok {
				calls = append(calls, t.p)
			}
		}
	}
	// Newest first across every kind.
	slices.SortStableFunc(calls, func(a, b paid) int { return cmp.Compare(b.at, a.at) })
	var out []rateCandidate
	for _, p := range calls {
		var sub reviews.Subject
		var ids []string
		var what, pair string
		switch {
		case p.tool.ID != "":
			// Our own tool: the operator is its owner, the pair the
			// subject's alone, as a relayed API's.
			sub, what, pair = p.tool, p.tool.Key, "swarmmemo/"+p.tool.ID
			ids = append(ids, sub.ID)
		case p.seller != "":
			if p.seller == account {
				continue
			}
			var handle string
			if err = tx.QueryRowContext(ctx, "SELECT coalesce((SELECT handle FROM identities WHERE account=? AND successor='' AND role='primary' ORDER BY handle='', created_at DESC LIMIT 1),'')", p.seller).Scan(&handle); err != nil {
				return nil, err
			}
			if sub, err = s.offeringSubject(p.seller, handle, p.name); err != nil {
				continue
			}
			ids = append(ids, sub.ID)
			if m, e := s.offeringSubjectAs(reviews.TypeMPP, p.seller, handle, p.name); e == nil {
				ids = append(ids, m.ID)
			}
			who := handle
			if who == "" {
				who = truncateUTF8(p.seller, 12) + "…"
			}
			what, pair = "@"+who+"'s "+p.name, p.seller+"/"+sub.ID
		default:
			var pub struct {
				Resource string `json:"resource"`
				Status   int    `json:"http_status"`
			}
			_ = json.Unmarshal([]byte(p.public), &pub)
			if pub.Status >= 400 {
				continue // not a call that succeeded
			}
			resURL, method, ok, err := s.x402ResourceAddress(ctx, tx, pub.Resource)
			if err != nil {
				return nil, err
			}
			if !ok {
				continue
			}
			if sub, err = reviews.Canonical(reviews.TypeX402, strings.ToUpper(method)+" "+resURL, s.subjectOptions()); err != nil {
				continue
			}
			ids = append(ids, sub.ID)
			what = resURL
			if u, e := url.Parse(resURL); e == nil && u.Host != "" {
				what = u.Host + u.Path
			}
			// A relayed API has no account behind it here: the pair is the
			// subject's alone.
			pair = "x402/" + sub.ID
		}
		reviewed, err := reviewedAny(ctx, tx, account, ids)
		if err != nil {
			return nil, err
		}
		if reviewed {
			continue
		}
		if len(what) > rateWhatBytes {
			what = truncateUTF8(what, rateWhatBytes) + "…"
		}
		out = append(out, rateCandidate{pair: pair, vars: map[string]string{"what": what, "call": p.id, "subject": sub.URI()}})
	}
	return out, nil
}

// reviewedAny reports whether account ever reviewed one of the subjects.
func reviewedAny(ctx context.Context, tx *sql.Tx, account string, subjects []string) (bool, error) {
	for _, id := range subjects {
		var one int
		err := tx.QueryRowContext(ctx, "SELECT 1 FROM reviews WHERE subject=? AND account=? LIMIT 1", id, account).Scan(&one)
		if err == nil {
			return true, nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return false, err
		}
	}
	return false, nil
}

// rateWorkerFact is rate_worker's when: a work item the caller requested
// with a submitted result waiting for its verdict (the one work.get reads
// first), no named reviewer, whose worker the caller never reviewed.
func (s *Store) rateWorkerFact(ctx context.Context, c *nudgeCall) (map[string]string, bool) {
	excluded, ok := s.rateSubjectOK(ctx, c)
	if !ok {
		return nil, false
	}
	target := ""
	if c.cmd.Operation == "work.get" {
		target = c.cmd.MessageID
		if target == "" {
			target = c.cmd.Target
		}
	}
	var cands []rateCandidate
	err := s.publicRead(ctx, func(ctx context.Context, tx *sql.Tx) error {
		q := `SELECT id,title,worker,fence,result_id FROM works WHERE requester=? AND state='submitted' AND worker<>'' AND worker<>requester AND result_id<>'' AND reviewer='' AND updated_at>?`
		args := []any{c.sub.account, c.now - rateLookbackSeconds}
		if target != "" {
			q, args = q+" AND id=?", append(args, target)
		}
		rows, err := tx.QueryContext(ctx, q+" ORDER BY updated_at DESC LIMIT ?", append(args, rateCandidates)...)
		if err != nil {
			return err
		}
		type waiting struct {
			id, title, worker, result string
			fence                     int64
		}
		var ws []waiting
		for rows.Next() {
			var w waiting
			if err = rows.Scan(&w.id, &w.title, &w.worker, &w.fence, &w.result); err != nil {
				rows.Close()
				return err
			}
			ws = append(ws, w)
		}
		if err = rows.Close(); err != nil {
			return err
		}
		for _, w := range ws {
			sub, err := reviews.Canonical(reviews.TypeAgent, w.worker, reviews.Options{})
			if err != nil {
				continue
			}
			reviewed, err := reviewedAny(ctx, tx, c.sub.account, []string{sub.ID})
			if err != nil {
				return err
			}
			if reviewed {
				continue
			}
			title := w.title
			if len(title) > rateWhatBytes {
				title = truncateUTF8(title, rateWhatBytes) + "…"
			}
			cands = append(cands, rateCandidate{pair: w.worker + "/" + sub.ID, vars: map[string]string{
				"work": w.id, "item": oneLine(title), "fence": strconv.FormatInt(w.fence, 10), "result": w.result}})
		}
		return nil
	})
	if err != nil || len(cands) == 0 {
		return nil, false
	}
	return s.rateFirst(ctx, c, "rate_worker", cands, excluded)
}
