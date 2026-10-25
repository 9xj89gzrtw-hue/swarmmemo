package board

import (
	"context"
	"fmt"
	"time"
)

// The claim cool-down (C580): a worker whose results on one standing task
// (or on one work item) were rejected WorkClaimCooldownRejects times within
// WorkClaimCooldownWindow cannot claim it again until WorkClaimCooldown
// after the last of those rejections. It stops a script resubmitting a
// template result every half hour, so the requester does not reject each by
// hand. Rejections count per account and across the accounts the existing
// link signals tie to it: one burst cluster (funnel_burst.go) or one shared
// network (sharedNetwork, the invite rewards' rule), so sibling keys share
// one count. Derived from the work history, nothing is stored; an accept
// never counts, and the requester's own transitions are not touched.
const (
	WorkClaimCooldownRejects       = 2
	WorkClaimCooldownWindow  int64 = 7 * 86400
	WorkClaimCooldown        int64 = 86400
)

// workClaimCooldownSQL is every rejection since ?2 with the account whose
// claim it judged (the claim of the same fence), on the work items %s picks.
const workClaimCooldownSQL = `SELECT %s, r.accepted_at FROM work_transitions r
 JOIN work_transitions c ON c.work_id=r.work_id AND c.fence=r.fence AND c.operation='work.claim'
 WHERE r.operation='work.reject' AND r.accepted_at>=?2 AND r.work_id IN (%s)`

// workClaimCooldownUntil is when account may claim w again, or 0 when it
// may now. On a standing task w is the task itself: its rejected results
// are the items it opened (standing_id, state cancelled).
func (s *Store) workClaimCooldownUntil(ctx context.Context, q workQuerier, w workRow, standing bool, account string, now int64) (int64, error) {
	from := now - WorkClaimCooldownWindow
	items := "?1"
	if standing {
		items = "SELECT id FROM works WHERE standing_id=?1 AND standing_id<>'' AND state='cancelled' AND updated_at>=?2"
	}
	rows, err := q.QueryContext(ctx, fmt.Sprintf(workClaimCooldownSQL, transitionAccountSQL("c"), items), w.ID, from)
	if err != nil {
		return 0, err
	}
	type reject struct {
		account string
		at      int64
	}
	var rejects []reject
	for rows.Next() {
		var r reject
		if err = rows.Scan(&r.account, &r.at); err != nil {
			rows.Close()
			return 0, err
		}
		rejects = append(rejects, r)
	}
	if err = closeRows(rows); err != nil || len(rejects) < WorkClaimCooldownRejects {
		return 0, err
	}
	linked := map[string]bool{account: true}
	checked := map[string]bool{account: true}
	var count int
	var last int64
	for _, r := range rejects {
		if r.account == "" {
			continue
		}
		if !checked[r.account] {
			checked[r.account] = true
			if linked[r.account], err = s.claimSiblings(ctx, q, account, r.account, from); err != nil {
				return 0, err
			}
		}
		if linked[r.account] {
			count++
			last = max(last, r.at)
		}
	}
	if count < WorkClaimCooldownRejects || now >= last+WorkClaimCooldown {
		return 0, nil
	}
	return last + WorkClaimCooldown, nil
}

// claimSiblings reports whether the existing link signals tie a and b: one
// burst cluster, or one network both wrote from since from.
func (s *Store) claimSiblings(ctx context.Context, q workQuerier, a, b string, from int64) (bool, error) {
	if same, err := sameBurstCluster(ctx, q, a, b); err != nil || same {
		return same, err
	}
	return s.sharedNetwork(ctx, q, a, b, from)
}

// workClaimCooldownText is the refusal's plain message.
func workClaimCooldownText(standing bool, until int64) string {
	what := "this task"
	if standing {
		what = "this standing task"
	}
	return fmt.Sprintf("Claims on %s are paused for you until %s: %d or more results on it from your account (or keys linked to it) were rejected in the last %d days, so each new claim waits %d hours after the latest rejection. Read the rejection reasons in work.history and change your result before you try again.",
		what, time.Unix(until, 0).UTC().Format(time.RFC3339), WorkClaimCooldownRejects, WorkClaimCooldownWindow/86400, WorkClaimCooldown/3600)
}

// refuseClaimCooldown is work.claim's 403 not_eligible while the cool-down
// holds.
func (s *Store) refuseClaimCooldown(ctx context.Context, q workQuerier, w workRow, standing bool, account string, now int64) error {
	until, err := s.workClaimCooldownUntil(ctx, q, w, standing, account, now)
	if err != nil || until == 0 {
		return err
	}
	return problem(403, "not_eligible", workClaimCooldownText(standing, until))
}
