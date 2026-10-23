package board

// The standing's reads (RFC 0021 §5, §13), as data for every surface:
// trust.get and GET /api/trust/standing (one breakdown), the per-viewer view,
// the public penalty log (trust.penalties, GET /api/trust/penalties), the
// operator's penalty and lift, and the operator dashboard's trust numbers.

import (
	"context"
	"database/sql"
	"errors"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"swarmmemo/internal/allowance"
	"swarmmemo/internal/trust"
)

// StandingSchema is the schema of the standing breakdown (trust.get).
const StandingSchema = 2

// TrustHistoryRuns is how many recent runs the trust surfaces' lines over
// time cover: an account's standing and accuracy on its breakdown, the
// top-5 share on /stats, the operator dashboard's shares.
const TrustHistoryRuns = 30

// lookupPublicAgent finds a key by fingerprint or handle among public
// agents (or the caller's own account), as trust.get always has.
func lookupPublicAgent(ctx context.Context, q allowance.Querier, target, caller string) (id, account string, err error) {
	err = q.QueryRowContext(ctx, "SELECT i.id,i.account FROM identities i WHERE (i.id=? OR i.handle=?) AND ("+publicAccountSQL("i.account")+" OR i.account=?) ORDER BY i.successor<>'' LIMIT 1",
		target, strings.ToLower(target), caller).Scan(&id, &account)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", errAgentNotFound()
	}
	return id, account, err
}

// readTrust is trust.get: an agent's standing with its breakdown (the
// StandingBreakdown); Data.viewer names the caller's own view when signed.
func (s *Store) readTrust(ctx context.Context, tx *sql.Tx, c Command, a actor, now int64) (Result, error) {
	if s.config.Features.Trust == TrustOff {
		return Result{}, allowanceError("service_unavailable")
	}
	target := c.Target
	if target == "" && a.signed {
		target = a.id
	}
	if target == "" {
		return Result{}, errNameTheAgent()
	}
	viewer := ""
	if a.signed && c.Data == "viewer" {
		viewer = a.account
	}
	out, err := s.standingBreakdown(ctx, tx, target, a.account, viewer, now)
	if err != nil {
		return Result{}, err
	}
	return Result{Data: out}, nil
}

// TrustStanding is GET /api/trust/standing?agent=FP[&viewer=FP]: the
// breakdown of agent's standing, with viewer's view of it when named.
func (s *Store) TrustStanding(ctx context.Context, agent, viewer string) (map[string]any, error) {
	if s.config.Features.Trust == TrustOff {
		return nil, allowanceError("service_unavailable")
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var viewerAccount string
	if viewer != "" {
		if _, viewerAccount, err = lookupPublicAgent(ctx, tx, viewer, ""); err != nil {
			return nil, err
		}
	}
	return s.standingBreakdown(ctx, tx, agent, "", viewerAccount, s.now().Unix())
}

// standingBreakdown is RFC 0021 §13's "Your trust" as data: the standing,
// its band and dollar figure; its own costs, each priced (world); what it
// keeps, received and passed on; its backers and whom it backs; its
// accuracy; its grace before inactivity decay; its penalty; what a penalty
// would burn; the next steps that raise it, with prices; and, with a viewer,
// the viewer's view (§5).
func (s *Store) standingBreakdown(ctx context.Context, q *sql.Tx, target, caller, viewer string, now int64) (map[string]any, error) {
	id, account, err := lookupPublicAgent(ctx, q, target, caller)
	if err != nil {
		return nil, err
	}
	p, err := s.trustParamsAt(ctx, q, now)
	if err != nil {
		return nil, err
	}
	run, _, err := trust.Latest(ctx, q)
	if err != nil {
		return nil, err
	}
	view, score, err := trust.CurrentStanding(ctx, q, account, p, now)
	if err != nil {
		return nil, err
	}
	parts := trust.Parts{World: []trust.WorldItem{}, Backers: []trust.FlowPart{}, Backs: []trust.FlowPart{}, AccuracyPPM: 1e6, NodeCapCents: p.NodeCapCents,
		FadePPM: 1e6, GraceDays: p.GraceDays, Burn: trust.BurnPreview{ProofRoots: []string{}, Backers: []trust.BackerAtRisk{}}}
	if score != nil {
		parts = score.Parts
	}
	ways, _, holds, err := s.standingWays(ctx, q, id, account, now)
	if err != nil {
		return nil, err
	}
	var next []StandingWay
	for _, w := range climbWays(ctx, ways) {
		if w.State == "none" || w.State == "lapsed" {
			next = append(next, w)
		}
	}
	sort.SliceStable(next, func(i, j int) bool { return wayMax(next[i]) > wayMax(next[j]) })
	climb := climbOf(p, view.StandingCents, climbWays(ctx, ways), holds)
	penalties, _, err := trust.PenaltyLog(ctx, q, 0, 5, account, now)
	if err != nil {
		return nil, err
	}
	caveats := []string{}
	if run.ID == 0 {
		caveats = append(caveats, "no trust run has finished yet: every standing is 0")
	} else if view.Stale {
		caveats = append(caveats, "the latest run is more than two days old, or the newest attempt was aborted")
	}
	if score == nil && run.ID != 0 {
		caveats = append(caveats, "not scored in the latest run: no public cost, judgement or activity in its window")
	}
	history, err := trust.AccountHistory(ctx, q, account, TrustHistoryRuns)
	if err != nil {
		return nil, err
	}
	roots := []string{account}
	for _, f := range append(append([]trust.FlowPart{}, parts.Backers...), parts.Backs...) {
		roots = append(roots, f.Root)
	}
	for _, b := range parts.Burn.Backers {
		roots = append(roots, b.Root)
	}
	names, err := rootHandles(ctx, q, roots)
	if err != nil {
		return nil, err
	}
	out := map[string]any{
		"schema": StandingSchema, "agent": id, "account": account, "root": view.Root, "boolean": false,
		"standing": view, "unit": "usd_cent", "summary": StandingSummary(view, parts, next, climb), "history": history, "names": names,
		"world": parts.World, "world_cents": parts.WorldCents, "direct_cents": parts.DirectCents, "root_world_cents": parts.RootWorldCents,
		"own_cents": parts.OwnCents, "received_cents": parts.ReceivedCents, "passed_cents": parts.PassedCents, "node_cap_cents": parts.NodeCapCents,
		"backers": parts.Backers, "backers_total": parts.BackersTotal, "backs": parts.Backs, "backs_total": parts.BacksTotal,
		"accuracy":   map[string]any{"ppm": parts.AccuracyPPM, "judged": parts.Judged, "min": 500000, "max": 2000000},
		"inactivity": map[string]any{"grace_days": parts.GraceDays, "grace_from_day": parts.GraceFromDay, "active_days": parts.ActiveDays, "fade_ppm": parts.FadePPM, "grace_total_days": p.GraceDays, "dormant_half_life_days": p.DormantHalfLifeDays},
		"penalty":    parts.Penalty, "penalties": penalties, "burn": parts.Burn,
		"next_steps": next, "climb": climb,
		"bands":      map[string]any{"proven_cents": p.Theta2Cents, "trusted_cents": p.NodeCapCents, "vote_floor_cents": p.VFloorCents, "c_ref_cents": p.CRefCents},
		"viewer":     nil,
		"recompute":  "/api/trust/runs/" + strconv.FormatInt(run.ID, 10),
		"caveats":    caveats,
	}
	if viewer != "" && run.ID != 0 {
		v, err := s.viewerStanding(ctx, q, run.ID, viewer, view.Root)
		if err != nil {
			return nil, err
		}
		out["viewer"] = v
	}
	return out, nil
}

// StandingSummary is the breakdown in one plain-English line, the line the
// MCP trust tool and the CLI lead with: "Standing 40¢, signed (own costs
// 40¢, no backers yet). Next: tier 1 at 100¢, 60¢ away: link a wallet
// (+~600¢)." Every number is the breakdown's own: the climb's nearer
// target and its free route then what paying costs (C342: "…, 50¢ away:
// about 5 active days free, or pay 50¢ now."), else its route's first
// step, else the largest next step.
func StandingSummary(view *trust.StandingView, parts trust.Parts, next []StandingWay, climb Climb) string {
	var b strings.Builder
	b.WriteString("Standing " + trust.CentsText(view.StandingCents) + ", " + view.Band + " (own costs " + trust.CentsText(parts.OwnCents))
	switch n := parts.BackersTotal; {
	case n == 1:
		b.WriteString(", backed by 1 agent " + trust.CentsText(parts.ReceivedCents))
	case n > 1:
		b.WriteString(", backed by " + strconv.FormatInt(n, 10) + " agents " + trust.CentsText(parts.ReceivedCents))
	default:
		b.WriteString(", no backers yet")
	}
	b.WriteString(").")
	if pen := parts.Penalty; pen != nil {
		b.WriteString(" Under a penalty as a " + pen.Role + " until " + time.Unix(pen.EndsAt, 0).UTC().Format("2006-01-02") + ".")
	}
	lower := func(s string) string { return strings.ToLower(s[:1]) + s[1:] }
	switch t := climb.Target; {
	case t != nil && climb.FreeRoute != nil:
		// Free first (C342), then paying as the faster way, at its cost.
		b.WriteString(" Next: " + t.Name + " at " + trust.CentsText(t.Cents) + ", " + trust.CentsText(t.GapCents) + " away: " + climb.FreeRoute.Text())
		if climb.PayCents > 0 {
			b.WriteString(", or pay " + trust.CentsText(climb.PayCents) + " now")
		}
		b.WriteString(".")
	case t != nil && len(climb.Route) > 0:
		step := climb.Route[0]
		b.WriteString(" Next: " + t.Name + " at " + trust.CentsText(t.Cents) + ", " + trust.CentsText(t.GapCents) + " away: " + lower(step.Label) + " (+~" + trust.CentsText(step.AddsCents) + ").")
	case len(next) > 0:
		w := next[0]
		b.WriteString(" Next: " + lower(w.Label))
		if w.AddsCents != nil && w.AddsCents.Max > 0 {
			b.WriteString(" (+~" + trust.CentsText(w.AddsCents.Max) + ")")
		}
		b.WriteString(".")
	}
	if view.Stale {
		b.WriteString(" The latest run is stale.")
	}
	return b.String()
}

// rootHandles names the account roots among roots (a root that is an
// account's fingerprint) by a public handle, for the breakdown's backers,
// backs and burn preview: {root: handle}. Other roots (a domain, a wallet)
// name themselves.
func rootHandles(ctx context.Context, q allowance.Querier, roots []string) (map[string]string, error) {
	out := map[string]string{}
	var accounts []any
	seen := map[string]bool{}
	for _, r := range roots {
		if len(r) == 64 && strings.Trim(r, "0123456789abcdef") == "" && !seen[r] {
			seen[r] = true
			accounts = append(accounts, r)
		}
	}
	if len(accounts) == 0 {
		return out, nil
	}
	rows, err := q.QueryContext(ctx, "SELECT i.account,i.handle FROM identities i WHERE i.handle<>'' AND i.account IN (?"+strings.Repeat(",?", len(accounts)-1)+") AND "+publicAccountSQL("i.account")+" ORDER BY i.successor<>'' DESC", accounts...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var account, handle string
		if err = rows.Scan(&account, &handle); err != nil {
			return nil, err
		}
		out[account] = handle
	}
	return out, rows.Err()
}

func wayMax(w StandingWay) int64 {
	if w.AddsCents == nil {
		return 0
	}
	return w.AddsCents.Max
}

// viewerCache keeps per-viewer views by (viewer root, run), at most
// viewerCacheMax, and the latest run's graph.
type viewerCache struct {
	mu    sync.Mutex
	run   int64
	graph *trust.Graph
	views map[string]map[string]int64
	order []string
}

// viewerCacheMax bounds the cached views (each one map of root standings).
const viewerCacheMax = 64

func (c *viewerCache) forget() {
	c.mu.Lock()
	c.run, c.graph, c.views, c.order = 0, nil, nil, nil
	c.mu.Unlock()
}

// viewerStanding is the viewer's view of the target root in run (§5): the
// run's flow with the viewer's root as one more source. It orders, never
// gates. Bounded (one Dinic run over the stored graph) and cached per
// (viewer, run).
func (s *Store) viewerStanding(ctx context.Context, q allowance.Querier, run int64, viewer, targetRoot string) (map[string]any, error) {
	c := &s.trust.views
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.run != run || c.graph == nil {
		g, ok, err := trust.LoadGraph(ctx, q, run)
		if err != nil {
			return nil, err
		}
		if !ok {
			return map[string]any{"account": viewer, "computed": false, "reason": "the run kept no graph"}, nil
		}
		c.run, c.graph, c.views, c.order = run, g, map[string]map[string]int64{}, nil
	}
	root, ok := c.graph.RootOf[viewer]
	if !ok {
		return map[string]any{"account": viewer, "computed": false, "reason": "the viewer is not in the latest run's graph: its view is the global standing"}, nil
	}
	view, ok := c.views[root]
	if !ok {
		var err error
		if view, _, err = c.graph.ViewerStanding(ctx, viewer); err != nil {
			return nil, err
		}
		c.views[root] = view
		c.order = append(c.order, root)
		if len(c.order) > viewerCacheMax {
			delete(c.views, c.order[0])
			c.order = c.order[1:]
		}
	}
	return map[string]any{"account": viewer, "root": root, "computed": true, "standing_cents": view[targetRoot], "run": run,
		"rule": "the run's flow with the viewer's root as one more source (node_cap plus its judgement edges' capacity); it orders what the viewer reads and never gates"}, nil
}

// TrustPenalties is the public penalty log (GET /api/trust/penalties,
// trust.penalties): entries newest first, before seq (0: from the newest),
// optionally only those naming account; next is the following page's
// cursor (0 at the end).
func (s *Store) TrustPenalties(ctx context.Context, before int64, limit int, account string) (entries []trust.PenaltyEntry, next int64, err error) {
	if s.config.Features.Trust == TrustOff {
		return nil, 0, allowanceError("service_unavailable")
	}
	err = trustDB{s}.Read(ctx, func(q allowance.Querier) (err error) {
		entries, next, err = trust.PenaltyLog(ctx, q, before, limit, account, s.now().Unix())
		return err
	})
	return entries, next, err
}

// readTrustPenalties is trust.penalties: the log through the command path
// (target: an agent whose entries to list; before: the cursor).
func (s *Store) readTrustPenalties(ctx context.Context, tx *sql.Tx, c Command, a actor, now int64) (Result, error) {
	if s.config.Features.Trust == TrustOff {
		return Result{}, allowanceError("service_unavailable")
	}
	limit := c.Limit
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	account := ""
	if c.Target != "" {
		_, acct, err := lookupPublicAgent(ctx, tx, c.Target, a.account)
		if err != nil {
			return Result{}, err
		}
		account = acct
	}
	entries, next, err := trust.PenaltyLog(ctx, tx, c.Before, limit, account, now)
	if err != nil {
		return Result{}, err
	}
	return Result{Data: map[string]any{"entries": entries, "next_before": next}}, nil
}

// PenalizeTrust records an operator's penalty (moderation, in the
// moderation standard's categories only, or override) on the named agents'
// accounts, with its evidence and public reason: pending until the next
// trust run applies it. It returns the entry's id.
func (s *Store) PenalizeTrust(ctx context.Context, trigger string, agents []string, evidence, reason, author string) (string, error) {
	var id string
	err := trustDB{s}.Write(ctx, func(q allowance.Querier) error {
		var members []string
		for _, agent := range agents {
			_, account, err := lookupPublicAgent(ctx, q, agent, "")
			if err != nil {
				return err
			}
			members = append(members, account)
		}
		var err error
		id, err = trust.NewPenalty(ctx, q, trigger, members, evidence, reason, author, s.now().Unix())
		return err
	})
	return id, err
}

// LiftTrustPenalty records an operator override reversing entry id, with a
// public reason. It returns the lift's id.
func (s *Store) LiftTrustPenalty(ctx context.Context, id, reason, author string) (string, error) {
	var lift string
	err := trustDB{s}.Write(ctx, func(q allowance.Querier) (err error) {
		lift, err = trust.LiftPenalty(ctx, q, id, reason, author, s.now().Unix())
		return err
	})
	return lift, err
}

// TrustDashboard is the operator dashboard's trust numbers (RFC 0021 §13)
// from the latest run: the share of the flow passed on that the operator's
// own accounts pass (operators: the funnel's exclude list, the one list of
// them), the top-5 sources' share, the penalties in force, and the accounts
// at or above the vote floor. nil before any run.
func (s *Store) trustDashboard(ctx context.Context, q allowance.Querier, operators map[string]bool, now int64) (map[string]any, error) {
	run, ok, err := trust.Latest(ctx, q)
	if err != nil || !ok {
		return nil, err
	}
	sum, ok, err := trust.RunSummaryOf(ctx, q, run.ID)
	if err != nil || !ok {
		return nil, err
	}
	scores, err := trust.RunScores(ctx, q, run.ID)
	if err != nil {
		return nil, err
	}
	// The same numbers over the recent runs, oldest first: the dashboard's
	// lines over time.
	recent, err := trust.RecentRuns(ctx, q, TrustHistoryRuns)
	if err != nil {
		return nil, err
	}
	history := make([]map[string]any, 0, len(recent))
	for _, r := range recent {
		rs, err := trust.RunScores(ctx, q, r.Run)
		if err != nil {
			return nil, err
		}
		history = append(history, map[string]any{"run": r.Run, "as_of": r.AsOf, "operator_passed_ppm": trust.PassedSharePPM(rs, operators),
			"top5_passed_ppm": r.Summary.Top5PassedPPM, "penalties_open": r.Summary.PenaltiesOpen, "above_vote_floor": r.Summary.AboveVoteFloor})
	}
	return map[string]any{"run": run.ID, "as_of": run.AsOf, "stale": run.Stale(now), "history": history,
		"operator_passed_ppm": trust.PassedSharePPM(scores, operators), "top5_passed_ppm": sum.Top5PassedPPM, "passed_cents": sum.PassedCents,
		"sources": sum.Sources, "penalties_open": sum.PenaltiesOpen, "penalised": sum.Penalised, "liable": sum.Liable,
		"above_vote_floor": sum.AboveVoteFloor, "bands": sum.Bands, "standing_cents": sum.StandingCents, "world_cents": sum.WorldCents}, nil
}
