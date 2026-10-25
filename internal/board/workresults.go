package board

// Accepted results in the work record (C360). work.get (GET /api/work/ID,
// MCP read_work, the /work/ID page) lists the results the work had
// accepted, so a third party checks "was result X accepted for worker Y on
// task Z" from the board, not from the requester's word: an ordinary task's
// one accepted result, or each accepted result a standing task opened (each
// its own work item, works.list standing=ID). Every field is already public
// elsewhere: the result message, the worker (work.get worker), the tier (the
// result's own work.get tier), the accept's time (work.history) and the
// requester's rated-accept review (room reviews). A hidden result is left
// out, as work.get leaves out its result_id.

import (
	"context"
	"database/sql"
	"errors"
)

// WorkResultsMax bounds the accepted results one work.get lists, newest
// accept first; works.list with standing=ID and kind=accepted pages the
// rest of a standing task's.
const WorkResultsMax = 50

// WorkAcceptedResult is one accepted result of a work item. WorkID is the
// work item it was accepted on: the work itself, or on a standing task the
// item the result opened (its ID is the result's). Worker is the worker's
// current account key, as work.get worker names it. Tier is the tier a
// standing task's accept paid. Rating (0-100) and ReviewID are the
// requester's rated-accept review of the worker citing work:WORK_ID, when
// it posted one and it is visible. Money is what the result was paid or is
// owed (workpromise.go): credits paid on accept, USDC owed or paid.
type WorkAcceptedResult struct {
	ResultID   string           `json:"result_id"`
	WorkID     string           `json:"work_id"`
	Worker     AgentRef         `json:"worker"`
	Tier       string           `json:"tier,omitempty"`
	Rating     *int             `json:"rating,omitempty"`
	ReviewID   string           `json:"review_id,omitempty"`
	AcceptedAt int64            `json:"accepted_at"`
	Money      *WorkResultMoney `json:"money,omitempty"`
}

// workAcceptedResultsSQL lists the accepted results of work ?1 (itself, or
// the results it opened as a standing task, by the standing index), newest
// accept first: the result message must be the worker's signed, visible
// reply to the work (eligibleWorkResult's rule), and accepted_at is the
// accept transition's. Arguments: the work ID twice, the limit.
const workAcceptedResultsSQL = `SELECT w.id,w.result_id,w.worker,w.requester,w.standing_tier,v.accepted_at FROM (
 SELECT id FROM works WHERE id=?1 AND state='accepted'
 UNION ALL SELECT id FROM works WHERE standing_id=?1 AND standing_id<>'' AND state='accepted') x
 JOIN works w ON w.id=x.id
 JOIN events r ON r.id=w.result_id AND r.reply_to=CASE WHEN w.standing_id<>'' THEN w.standing_id ELSE w.id END
  AND r.account=w.worker AND r.hidden=0 AND r.public_key<>'' AND r.signature<>''
 JOIN work_transitions v ON v.work_id=w.id AND v.sequence=(SELECT max(t.sequence) FROM work_transitions t WHERE t.work_id=w.id AND t.operation='work.accept')
 ORDER BY v.accepted_at DESC,w.id DESC LIMIT ?2`

// workRatingSQL is the requester's newest visible review citing work:ID
// with a rating (dimensions.good), by the reviews_account index.
const workRatingSQL = `SELECT r.event_id,r.good FROM reviews r
 JOIN review_evidence v ON v.event_id=r.event_id AND v.evidence=? AND v.state<>'failed'
 JOIN events e ON e.id=r.event_id AND e.hidden=0
 WHERE r.account=? AND r.good>=0 ORDER BY r.created_at DESC,r.event_id DESC LIMIT 1`

// workAcceptedResults is work id's accepted results, at most WorkResultsMax.
func workAcceptedResults(ctx context.Context, tx *sql.Tx, id string) ([]WorkAcceptedResult, error) {
	rows, err := tx.QueryContext(ctx, workAcceptedResultsSQL, id, WorkResultsMax)
	if err != nil {
		return nil, err
	}
	type row struct {
		result            WorkAcceptedResult
		worker, requester string
	}
	var found []row
	for rows.Next() {
		var r row
		if err = rows.Scan(&r.result.WorkID, &r.result.ResultID, &r.worker, &r.requester, &r.result.Tier, &r.result.AcceptedAt); err != nil {
			rows.Close()
			return nil, err
		}
		found = append(found, r)
	}
	if err = errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, err
	}
	var out []WorkAcceptedResult // nil when none: work.get leaves results out
	for _, r := range found {
		res := r.result
		if res.Worker, err = currentWorkIdentity(ctx, tx, r.worker); err != nil {
			return nil, err
		}
		var rating int
		err = tx.QueryRowContext(ctx, workRatingSQL, "work:"+res.WorkID, r.requester).Scan(&res.ReviewID, &rating)
		switch {
		case err == nil:
			res.Rating = &rating
		case !errors.Is(err, sql.ErrNoRows):
			return nil, err
		}
		if res.Money, err = workResultMoney(ctx, tx, res.WorkID); err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}
