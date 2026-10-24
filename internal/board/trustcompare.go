package board

// The cutover check (C320c): "swarmmemo trust compare RUN_OLD RUN_NEW" puts
// two runs side by side per account, so the steward sees on a copy of the
// prod database what an account had and what it gets: its band (an old
// run's tier), its standing (an old run's collateral), its vote weight (the
// old run's stored weight; the new one floored for a seasoned account) and
// its daily allowance share per resource (the largest share the tier
// waterfall gave it within ledger.TransitionFloorDays, against what a claim
// now would issue with the new run's standing, the transition floor
// included). Operator-only: nothing public reads it.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"

	"swarmmemo/internal/allowance"
	"swarmmemo/internal/ledger"
	"swarmmemo/internal/trust"
)

// CompareResources are the resources a comparison shows, in order.
var CompareResources = []allowance.Resource{allowance.PostBytes, allowance.MemoryBytes, allowance.Credit}

// TrustCompareSide is one run's reading of an account.
type TrustCompareSide struct {
	Band    string `json:"band"` // the band, or "tier N" for a run before version 8
	Cents   int64  `json:"cents"`
	VotePPM int64  `json:"vote_ppm"`
}

// TrustCompareShare is one resource's daily share: the waterfall's (Old),
// the share rule's own (Rule) and what a claim issues (New, the transition
// floor included).
type TrustCompareShare struct {
	Old  int64 `json:"old"`
	Rule int64 `json:"rule"`
	New  int64 `json:"new"`
}

// TrustCompareRow is one account.
type TrustCompareRow struct {
	Account  string                                   `json:"account"`
	Handle   string                                   `json:"handle"`
	Seasoned bool                                     `json:"seasoned"`
	Old      TrustCompareSide                         `json:"old"`
	New      TrustCompareSide                         `json:"new"`
	Shares   map[allowance.Resource]TrustCompareShare `json:"shares"`
}

// TrustComparison is the whole comparison and its counts.
type TrustComparison struct {
	OldRun     int64             `json:"old_run"`
	NewRun     int64             `json:"new_run"`
	OldVersion int64             `json:"old_version"`
	NewVersion int64             `json:"new_version"`
	Rows       []TrustCompareRow `json:"rows"`
	// Counts: accounts with standing above 0 in each run, whose vote weight
	// fell, and per resource whose share fell below the waterfall's.
	OldStanding int64                        `json:"old_standing"`
	NewStanding int64                        `json:"new_standing"`
	VoteFell    int64                        `json:"vote_fell"`
	ShareFell   map[allowance.Resource]int64 `json:"share_fell"`
}

// TrustCompare reads two runs and the allowance as of now, in one read
// transaction.
func (s *Store) TrustCompare(ctx context.Context, oldRun, newRun int64) (*TrustComparison, error) {
	if s.config.Features.Trust == TrustOff {
		return nil, allowanceError("service_unavailable")
	}
	now := s.now().Unix()
	out := &TrustComparison{OldRun: oldRun, NewRun: newRun, ShareFell: map[allowance.Resource]int64{}}
	err := trustDB{s}.Read(ctx, func(q allowance.Querier) error {
		p, err := s.trustParamsAt(ctx, q, now)
		if err != nil {
			return err
		}
		if out.OldVersion, err = runVersion(ctx, q, oldRun); err != nil {
			return err
		}
		if out.NewVersion, err = runVersion(ctx, q, newRun); err != nil {
			return err
		}
		type side struct {
			root string
			TrustCompareSide
		}
		read := func(run, version int64) (map[string]side, error) {
			rows, err := q.QueryContext(ctx, "SELECT account,root,collateral,tier,weight_ppm FROM trust_scores WHERE run_id=?", run)
			if err != nil {
				return nil, err
			}
			m := map[string]side{}
			for rows.Next() {
				var x side
				var account string
				var tier int64
				if err = rows.Scan(&account, &x.root, &x.Cents, &tier, &x.VotePPM); err != nil {
					rows.Close()
					return nil, err
				}
				x.Band = "tier " + strconv.FormatInt(tier, 10)
				if version >= trust.UnifiedVersion {
					x.Band = allowance.Band(tier).Name()
				}
				m[account] = x
			}
			return m, closeRows(rows)
		}
		olds, err := read(oldRun, out.OldVersion)
		if err != nil {
			return err
		}
		news, err := read(newRun, out.NewVersion)
		if err != nil {
			return err
		}
		accounts := make([]string, 0, len(olds)+len(news))
		for a := range olds {
			accounts = append(accounts, a)
		}
		for a := range news {
			if _, ok := olds[a]; !ok {
				accounts = append(accounts, a)
			}
		}
		day := now / 86400
		for _, a := range accounts {
			o, n := olds[a], news[a]
			if n.root == "" {
				n.root = a
			}
			row := TrustCompareRow{Account: a, Old: o.TrustCompareSide, Shares: map[allowance.Resource]TrustCompareShare{}}
			if row.Old.Band == "" {
				row.Old.Band = "none"
			}
			if err = q.QueryRowContext(ctx, "SELECT coalesce(max(handle),'') FROM identities WHERE account=? AND successor=''", a).Scan(&row.Handle); err != nil {
				return err
			}
			if row.Seasoned, err = seasonedVoter(ctx, q, a, now); err != nil {
				return err
			}
			row.New = TrustCompareSide{Band: p.Band(n.Cents).Name(), Cents: n.Cents, VotePPM: p.FlooredVoteWeight(row.Seasoned, n.Cents)}
			st := allowance.Standing{Band: p.Band(n.Cents), Cents: n.Cents, ShareCents: min(n.Cents, p.NodeCapCents), Root: n.root}
			for _, r := range CompareResources {
				var sh TrustCompareShare
				if sh.Old, err = ledger.LegacyShare(ctx, q, r, day, a); err != nil {
					return err
				}
				if s.ledger.led != nil {
					got, err := s.ledger.led.ProspectiveShare(ctx, q, r, st, a, now)
					var refused *allowance.Err
					if err != nil && !errors.As(err, &refused) {
						return err
					}
					sh.Rule, sh.New = got.Rule, got.Floor+got.Standing
				}
				if sh.New < sh.Old {
					out.ShareFell[r]++
				}
				row.Shares[r] = sh
			}
			if row.Old.Cents > 0 {
				out.OldStanding++
			}
			if row.New.Cents > 0 {
				out.NewStanding++
			}
			if row.New.VotePPM < row.Old.VotePPM {
				out.VoteFell++
			}
			out.Rows = append(out.Rows, row)
		}
		sort.Slice(out.Rows, func(i, j int) bool {
			x, y := out.Rows[i], out.Rows[j]
			if x.New.Cents != y.New.Cents {
				return x.New.Cents > y.New.Cents
			}
			return x.Account < y.Account
		})
		return nil
	})
	return out, err
}

// WriteTrustComparison writes c as text: a line per account (fingerprint
// prefix, handle, band, standing in cents, vote weight, and per resource the
// waterfall's share → the share a claim issues, with the share rule's own in
// brackets when the transition floor raised it; bytes in KiB), then the
// counts.
func WriteTrustComparison(w io.Writer, c *TrustComparison) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "trust compare: run %d (version %d) -> run %d (version %d)\n", c.OldRun, c.OldVersion, c.NewRun, c.NewVersion)
	head := "account\thandle\tband\tstanding ¢\tvote"
	for _, r := range CompareResources {
		unit := ""
		if r != allowance.Credit {
			unit = " KiB"
		}
		head += "\t" + string(r) + unit
	}
	fmt.Fprintln(tw, head)
	amount := func(r allowance.Resource, n int64) string {
		if r == allowance.Credit {
			return strconv.FormatInt(n, 10)
		}
		return strconv.FormatInt(n>>10, 10)
	}
	vote := func(ppm int64) string { return strconv.FormatFloat(float64(ppm)/1e6, 'f', 2, 64) }
	for _, row := range c.Rows {
		handle := row.Handle
		if handle == "" {
			handle = "-"
		}
		line := fmt.Sprintf("%s\t%s\t%s -> %s\t%d -> %d\t%s -> %s", row.Account[:min(12, len(row.Account))], handle, row.Old.Band, row.New.Band,
			row.Old.Cents, row.New.Cents, vote(row.Old.VotePPM), vote(row.New.VotePPM))
		for _, r := range CompareResources {
			sh := row.Shares[r]
			cell := amount(r, sh.Old) + " -> " + amount(r, sh.New)
			if sh.New > sh.Rule {
				cell += " (rule " + amount(r, sh.Rule) + ")"
			}
			line += "\t" + cell
		}
		fmt.Fprintln(tw, line)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	fell := ""
	for _, r := range CompareResources {
		fell += fmt.Sprintf(", %s %d", r, c.ShareFell[r])
	}
	_, err := fmt.Fprintf(w, "accounts with standing: %d -> %d; vote weight fell: %d; share below the waterfall's: %s\n",
		c.OldStanding, c.NewStanding, c.VoteFell, strings.TrimPrefix(fell, ", "))
	return err
}

// runVersion is a finished run's parameter version.
func runVersion(ctx context.Context, q allowance.Querier, run int64) (int64, error) {
	var v int64
	err := q.QueryRowContext(ctx, "SELECT params_version FROM trust_runs WHERE id=? AND state='done'", run).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, problem(404, "not_found", "No finished trust run "+strconv.FormatInt(run, 10)+"; /api/trust/runs lists them.")
	}
	return v, err
}
