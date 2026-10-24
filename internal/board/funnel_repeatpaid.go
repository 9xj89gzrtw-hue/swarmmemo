package board

import (
	"context"
	"database/sql"
	"sort"
)

// Unprompted repeat paid use (C541): whether agents pay for SwarmMemo again
// on their own, or only while a bounty asks them to. Raw paid-call counts
// mislead when most payers are bounty hunters making the call a task
// requires, so this counts the paid calls of agents with no work as a
// worker in the days before the call, and those who came back on another
// day. Operator-only (`swarmmemo funnel kpi`, /admin/funnel), aggregates
// only: never an agent, never split by who runs one. Read-only: plain
// reads through the pool, never under a held transaction.

// RepeatPaidLookbackDays is how far before a paid call a worker's work
// makes it prompted.
const RepeatPaidLookbackDays = 7

// RepeatPaidMinDays is the distinct UTC days of paid calls that make a
// payer a repeat payer.
const RepeatPaidMinDays = 2

// RepeatPaidKinds are the kinds of paid call, as FunnelRepeatPaid.ByKind
// names them: a priced tool call (service_calls, cost>0, not x402), a cash
// call through the x402 rail (service_calls service x402, cost>0), and a
// settled offering call by a signed caller (offering_calls).
var RepeatPaidKinds = []string{"service", "x402", "offering"}

// RepeatPaidCounts is one row: distinct payers, those with paid calls on
// RepeatPaidMinDays or more distinct UTC days, and the paid calls.
type RepeatPaidCounts struct {
	Payers       int `json:"payers"`
	RepeatPayers int `json:"repeat_payers"`
	Calls        int `json:"paid_calls"`
}

// RepeatPaidPair is a row with and without the unprompted filter.
type RepeatPaidPair struct {
	Unprompted RepeatPaidCounts `json:"unprompted"`
	All        RepeatPaidCounts `json:"all"`
}

// FunnelRepeatPaid is the unprompted repeat paid use over a window.
//
// A paid call is unprompted when its account has no work.claim, work.renew
// or work.submit of its own, and no work.accept of a work it is the worker
// of, in the RepeatPaidLookbackDays before the call. An unprompted payer
// has an unprompted paid call; an unprompted repeat payer has unprompted
// paid calls on RepeatPaidMinDays or more distinct UTC days. Total counts a
// payer once over every kind (repeat: days of any kind); ByKind counts
// each kind alone. The exclude list's accounts and burst cluster members
// are left out; BurstPayersLeftOut says how many burst payers that was.
type FunnelRepeatPaid struct {
	From               int64                     `json:"from"`
	To                 int64                     `json:"to"`
	LookbackDays       int                       `json:"lookback_days"`
	MinDays            int                       `json:"repeat_min_days"`
	Total              RepeatPaidPair            `json:"total"`
	ByKind             map[string]RepeatPaidPair `json:"by_kind"`
	BurstPayersLeftOut int                       `json:"burst_payers_left_out"`
}

const (
	// repeatPaidServiceSQL is the priced tool calls and x402 cash calls
	// that ran: the same rows the funnel's paid_call act counts.
	repeatPaidServiceSQL = `SELECT account, CASE WHEN service='x402' THEN 'x402' ELSE 'service' END, created_at
 FROM service_calls WHERE state='done' AND cost>0 AND account<>'' AND created_at BETWEEN ?1 AND ?2`
	// repeatPaidOfferingSQL is the settled offering calls of a signed
	// caller, on the caller key's account (or a delegated key's parent).
	repeatPaidOfferingSQL = `SELECT coalesce(i.account, d.parent_account, ''), 'offering', c.settled_at
 FROM offering_calls c LEFT JOIN identities i ON i.id=c.caller LEFT JOIN delegations d ON d.child_id=c.caller
 WHERE c.caller<>'' AND c.settled_at>0 AND c.settled_at BETWEEN ?1 AND ?2`
	// repeatPaidWorkSQL is each account's work as a worker: its own
	// claims, renewals and submits, and the accepts of works it holds.
	repeatPaidWorkSQL = `SELECT coalesce(i.account, d.parent_account, ''), t.accepted_at
 FROM work_transitions t LEFT JOIN identities i ON i.id=t.author LEFT JOIN delegations d ON d.child_id=t.author
 WHERE t.operation IN ('work.claim','work.renew','work.submit') AND t.accepted_at BETWEEN ?1 AND ?2
 UNION ALL
 SELECT w.worker, t.accepted_at FROM work_transitions t JOIN works w ON w.id=t.work_id
 WHERE t.operation='work.accept' AND w.worker<>'' AND t.accepted_at BETWEEN ?1 AND ?2`
)

// funnelRepeatPaid computes FunnelRepeatPaid over the paid calls in
// [from, to].
func (s *Store) funnelRepeatPaid(ctx context.Context, from, to int64, excluded map[string]bool) (FunnelRepeatPaid, error) {
	out := FunnelRepeatPaid{From: from, To: to, LookbackDays: RepeatPaidLookbackDays, MinDays: RepeatPaidMinDays, ByKind: map[string]RepeatPaidPair{}}
	bursts, err := s.FunnelBursts(ctx)
	if err != nil {
		return out, err
	}
	burst := bursts.Members()
	type call struct {
		kind string
		at   int64
	}
	calls := map[string][]call{}
	burstPayers := map[string]bool{}
	for _, q := range []string{repeatPaidServiceSQL, repeatPaidOfferingSQL} {
		err = repeatPaidScan(ctx, s.db, q, from, to, func(r *sql.Rows) error {
			var account string
			var c call
			if err := r.Scan(&account, &c.kind, &c.at); err != nil {
				return err
			}
			_, inBurst := burst[account]
			switch {
			case account == "" || excluded[account]:
			case inBurst:
				burstPayers[account] = true
			default:
				calls[account] = append(calls[account], c)
			}
			return nil
		})
		if err != nil {
			return out, err
		}
	}
	out.BurstPayersLeftOut = len(burstPayers)
	lookback := int64(RepeatPaidLookbackDays) * 86400
	work := map[string][]int64{}
	err = repeatPaidScan(ctx, s.db, repeatPaidWorkSQL, from-lookback, to, func(r *sql.Rows) error {
		var account string
		var at int64
		if err := r.Scan(&account, &at); err != nil {
			return err
		}
		if calls[account] != nil {
			work[account] = append(work[account], at)
		}
		return nil
	})
	if err != nil {
		return out, err
	}
	// prompted: a work as a worker in [at-lookback, at].
	prompted := func(account string, at int64) bool {
		ts := work[account]
		i := sort.Search(len(ts), func(i int) bool { return ts[i] >= at-lookback })
		return i < len(ts) && ts[i] <= at
	}
	// days: a payer's distinct UTC days, total and per kind.
	type tally struct{ all, unprompted map[int64]bool }
	add := func(c *RepeatPaidCounts, t map[int64]bool, n int) {
		if n == 0 {
			return
		}
		c.Payers++
		c.Calls += n
		if len(t) >= RepeatPaidMinDays {
			c.RepeatPayers++
		}
	}
	byKind := map[string]*RepeatPaidPair{}
	for _, k := range RepeatPaidKinds {
		byKind[k] = &RepeatPaidPair{}
	}
	for account, list := range calls {
		ts := work[account]
		sort.Slice(ts, func(i, j int) bool { return ts[i] < ts[j] })
		total := tally{map[int64]bool{}, map[int64]bool{}}
		kinds := map[string]*tally{}
		nAll, nUnprompted := map[string]int{}, map[string]int{}
		for _, c := range list {
			k := kinds[c.kind]
			if k == nil {
				k = &tally{map[int64]bool{}, map[int64]bool{}}
				kinds[c.kind] = k
			}
			day := c.at / 86400
			total.all[day], k.all[day] = true, true
			nAll[c.kind]++
			if !prompted(account, c.at) {
				total.unprompted[day], k.unprompted[day] = true, true
				nUnprompted[c.kind]++
			}
		}
		var sumAll, sumUnprompted int
		for kind, k := range kinds {
			p := byKind[kind]
			add(&p.All, k.all, nAll[kind])
			add(&p.Unprompted, k.unprompted, nUnprompted[kind])
			sumAll += nAll[kind]
			sumUnprompted += nUnprompted[kind]
		}
		add(&out.Total.All, total.all, sumAll)
		add(&out.Total.Unprompted, total.unprompted, sumUnprompted)
	}
	for k, p := range byKind {
		out.ByKind[k] = *p
	}
	return out, nil
}

// funnelRepeatPaidExcluding is funnelRepeatPaid with the exclude list read.
func (s *Store) funnelRepeatPaidExcluding(ctx context.Context, from, to int64) (FunnelRepeatPaid, error) {
	excluded, err := s.funnelExcluded(ctx)
	if err != nil {
		return FunnelRepeatPaid{}, err
	}
	return s.funnelRepeatPaid(ctx, from, to, excluded)
}

// repeatPaidScan runs q over [from, to] and scans each row.
func repeatPaidScan(ctx context.Context, db *sql.DB, q string, from, to int64, scan func(*sql.Rows) error) error {
	rows, err := db.QueryContext(ctx, q, from, to)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		if err = scan(rows); err != nil {
			return err
		}
	}
	return rows.Err()
}
