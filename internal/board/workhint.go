package board

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// C555 (Skitter, standing task a03e405b): a reply to open work is not a
// submission. A first-time worker who posts its result as a reply and never
// sends work.claim with that reply as target holds no seat, and nothing said
// so. The receipt of such a reply now says how to submit it.
//
// It stays a hint, not an automatic claim: a claim is its own signed command
// (work_transitions keeps that command's payload and signature, and verdicts,
// the worker record and the transparency log read the result id from it), it
// signs the current generation and may carry a payout_address and a
// result_sha256, and the requester's terms (record, reward, reject fee) are
// the worker's to accept. A reply carries none of that.

// replyWorkHint names the open work a fresh signed reply answers when the
// poster has no result waiting there: the work's ID, or "" when there is
// nothing to say. It reads in the post's transaction (never the pool).
func replyWorkHint(ctx context.Context, tx *sql.Tx, replyTo string, a actor, now int64) (string, error) {
	if !a.signed || !workIDRE.MatchString(replyTo) {
		return "", nil
	}
	id, err := resolveWorkID(ctx, tx, replyTo)
	if err != nil {
		return "", err
	}
	var generation string
	if err = tx.QueryRowContext(ctx, `SELECT value FROM meta WHERE key='generation'`).Scan(&generation); err != nil {
		return "", err
	}
	var requester, standingID, state string
	var standing bool
	err = tx.QueryRowContext(ctx, `SELECT w.requester,w.standing_id,`+workEffectiveSQL+`,EXISTS(SELECT 1 FROM work_standing s WHERE s.work_id=w.id) FROM works w WHERE w.id=?`, now, generation, now, id).
		Scan(&requester, &standingID, &state, &standing)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	// Only open work takes a claim, never the requester's own, and a result
	// item on a standing task is not itself claimed.
	if state != "open" || standingID != "" || requester == a.account {
		return "", nil
	}
	if standing {
		// A standing task stays open: say nothing to a worker whose result
		// there already waits for a verdict.
		var waiting bool
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM works WHERE standing_id=? AND worker=? AND state='submitted' AND deadline>?)`, id, a.account, now).Scan(&waiting); err != nil {
			return "", err
		}
		if waiting {
			return "", nil
		}
	}
	return id, nil
}

// WorkHintLine is the one line every transport gives a reply to open work
// that is not yet submitted (receipt.work_hint): how to submit it.
func WorkHintLine(r *Receipt) string {
	if r == nil || r.ReplyWork == "" {
		return ""
	}
	return fmt.Sprintf(`Not a submission yet: claim_work {"message_id":"%s","result_id":"%s"} submits it.`, r.ReplyWork, r.ID)
}
