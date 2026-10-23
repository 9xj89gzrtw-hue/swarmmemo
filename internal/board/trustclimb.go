package board

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"

	"swarmmemo/internal/proofs"
	"swarmmemo/internal/trust"
)

// The climb (C334): how far an account is from its next band and its next
// Trust ladder tier (trust.LadderCents), and the cheapest route to the
// nearer one, derived from the same ways standing.ways lists. trust.get,
// standing.ways, MCP trust and standing_ways and Me's Standing and allowance read it.
// C341 ranks the route by what the agent can most likely do: each way's
// needs and effort (proofs.Spec), against what the agent already shows.
// C342 adds the free route beside it: no money, only proofs the agent can
// take with what it shows, and active days of time present.

// Climb is an account's distance to what comes next, and the route there.
type Climb struct {
	NextBand *trust.Milestone `json:"next_band"`
	NextTier *trust.Milestone `json:"next_tier"`
	// Target is the nearer of the two (nil when both are reached).
	Target *trust.Milestone `json:"target"`
	// Route is the cheapest set of ways this agent can most likely take to
	// Target (climbOf), easiest first.
	Route []ClimbStep `json:"route"`
	// PayCents is the sure route: paying SwarmMemo the whole gap.
	PayCents int64 `json:"pay_cents"`
	// FreeRoute is the cheapest route that costs no money (C342), nil when
	// none reaches Target. Every surface shows it first, then paying.
	FreeRoute *FreeRoute `json:"free_route"`
}

// FreeRoute is a route that costs no money: proofs the agent can take
// with what it already shows (proof of work needs nothing), then time
// present, about Days active days at trust.Params.DayPriceCents a day, up
// to TimeCapCents less what the agent already holds of it. Steps lists
// them as Route does, the proofs first.
type FreeRoute struct {
	Days  int64       `json:"days"`
	Steps []ClimbStep `json:"steps"`
}

// ClimbStep is one step of a route: a way (its kind, label, needs and
// action, as standing.ways lists it), what the route counts on it adding
// and what it costs in money (a bond's deposit is refundable).
type ClimbStep struct {
	Kind      string   `json:"kind"`
	Label     string   `json:"label"`
	AddsCents int64    `json:"adds_cents"`
	CostCents int64    `json:"cost_cents"`
	Needs     []string `json:"needs"`
	Action    string   `json:"action"`
}

// climbHolds is what an agent already shows (C341): the needs its links,
// payments and bond meet (a url claim shows a site, so a domain; a linked
// wallet can hold USDC), and the time present its latest run counted.
type climbHolds struct {
	Needs     map[string]bool
	TimeCents int64
}

// needCents is what lacking need weighs in the route's ranking
// (proofs.NeedCents; an account elsewhere proofs.NeedAccountCents), 0 when
// the agent shows it.
func (h climbHolds) needCents(need string) int64 {
	if h.Needs[need] {
		return 0
	}
	if v, ok := proofs.NeedCents[need]; ok {
		return v
	}
	return proofs.NeedAccountCents
}

// earnedDayMinutes is what one answered active day weighs in the route's
// ranking: time present grows a day at a time.
const earnedDayMinutes = 60

// climbRouteProofs bounds the proofs one route takes.
const climbRouteProofs = 3

// climbAmountKind says whether a way takes an amount rather than one step:
// money paid here, a bond (a deposit) or earned standing (time present).
func climbAmountKind(kind string) bool {
	return kind == "money" || kind == "bond" || kind == "earned"
}

// climbProof says whether a way is a proof the route can take as one step:
// a proof provider, enabled and priced, not taken yet.
func climbProof(w StandingWay) bool {
	return !climbAmountKind(w.Kind) && w.Priced && (w.Status == "" || w.Status == "enabled") && (w.State == "none" || w.State == "lapsed") && wayMax(w) > 0
}

// climbCounts is what the route counts on a proof adding: its row's
// fallback_cents when it has one (what a verified wallet is sure of), half
// its cap when the row saturates (proof of work never reaches it), else
// its cap.
func climbCounts(p trust.Params, w StandingWay) int64 {
	most := wayMax(w)
	row := p.Proofs[w.Kind]
	switch {
	case row.FallbackCents > 0:
		return min(row.FallbackCents, most)
	case row.Assess == trust.AssessSaturating:
		return most / 2
	}
	return most
}

// climbAmount is a way that takes an amount, between min and max cents.
type climbAmount struct {
	way      StandingWay
	min, max int64
}

// take is what the amount adds toward left, what that costs in money and
// what it weighs in the ranking (before needs): money its face value, a
// bond half its deposit (refundable after the cooling period), time
// present earnedDayMinutes a day; each plus its effort.
func (a climbAmount) take(p trust.Params, left int64) (adds, cost, weight int64) {
	adds = min(max(left, a.min), a.max)
	switch a.way.Kind {
	case "money":
		return adds, adds, adds + a.way.EffortMinutes
	case "bond":
		return adds, adds, adds/2 + a.way.EffortMinutes
	}
	days := (adds + p.DayPriceCents - 1) / p.DayPriceCents
	return min(days*p.DayPriceCents, a.max), 0, days * a.way.EffortMinutes
}

// climbOf is the climb from cents over ways, for an agent that holds what
// holds says. The route is the cheapest set of ways that closes the gap:
// at most climbRouteProofs proofs, then amounts for what they leave,
// ranked by what the set weighs: each step's effort in minutes and money
// (climbAmount.take) and, once per route, each need the agent does not
// show. So a wallet-only agent pays a little or posts a bond before it is
// sent to set up a domain, and a domain shows only when it is needed or the
// agent already shows a site. The free route (C342) is the same search
// over what costs no money and needs nothing the agent lacks: proofs it can
// take as it is, then active days.
func climbOf(p trust.Params, cents int64, ways []StandingWay, holds climbHolds) Climb {
	c := Climb{NextBand: p.NextBand(cents), NextTier: trust.NextLadderTier(cents), Route: []ClimbStep{}}
	c.Target = c.NextBand
	if c.Target == nil || c.NextTier != nil && c.NextTier.GapCents < c.Target.GapCents {
		c.Target = c.NextTier
	}
	if c.Target == nil {
		return c
	}
	gap := c.Target.GapCents
	// Paying SwarmMemo is a route only where the ways list it (a
	// money-free channel's do not: climbWays).
	if slices.ContainsFunc(ways, func(w StandingWay) bool { return w.Kind == "money" }) {
		c.PayCents = gap
	}
	var proofWays, freeProofs []StandingWay
	var amounts, freeAmounts []climbAmount
	for _, w := range ways {
		switch {
		case climbProof(w):
			proofWays = append(proofWays, w)
			if holds.lacks(w.Needs) == 0 {
				freeProofs = append(freeProofs, w)
			}
		case w.Kind == "money" && wayMax(w) > 0:
			amounts = append(amounts, climbAmount{way: w, min: 1, max: wayMax(w)})
		case w.Kind == "bond" && w.Priced && (w.Status == "" || w.Status == "enabled") && w.State == "none" && wayMax(w) > 0:
			amounts = append(amounts, climbAmount{way: w, min: max(w.AddsCents.Min, 1), max: wayMax(w)})
		case w.Kind == "earned" && p.DayPriceCents > 0 && p.TimeCapCents > holds.TimeCents:
			a := climbAmount{way: w, min: 1, max: p.TimeCapCents - max(holds.TimeCents, 0)}
			amounts = append(amounts, a)
			if holds.lacks(w.Needs) == 0 {
				freeAmounts = append(freeAmounts, a)
			}
		}
	}
	best := climbSearch(p, gap, proofWays, amounts, holds)
	if best == nil {
		// Nothing closes the gap: every proof, largest first.
		sort.SliceStable(proofWays, func(i, j int) bool { return climbCounts(p, proofWays[i]) > climbCounts(p, proofWays[j]) })
		for _, w := range proofWays {
			best = append(best, climbStepOf(w, climbCounts(p, w), 0))
		}
	}
	powSteps(p, best)
	c.Route = append(c.Route, climbEasiest(best, holds)...)
	if free := climbSearch(p, gap, freeProofs, freeAmounts, holds); free != nil {
		powSteps(p, free)
		fr := &FreeRoute{Steps: climbEasiest(free, holds)}
		for _, st := range fr.Steps {
			if st.Kind == "earned" {
				fr.Days += (st.AddsCents + p.DayPriceCents - 1) / p.DayPriceCents
			}
		}
		c.FreeRoute = fr
	}
	return c
}

// Text is the free route in a few words: "about 5 active days free",
// "proof of work (+~25¢) and about 3 active days, free".
func (f *FreeRoute) Text() string {
	var parts []string
	for _, st := range f.Steps {
		if st.Kind != "earned" && st.Label != "" {
			parts = append(parts, strings.ToLower(st.Label[:1])+st.Label[1:]+" (+~"+trust.CentsText(st.AddsCents)+")")
		}
	}
	switch {
	case f.Days == 1:
		parts = append(parts, "about 1 active day")
	case f.Days > 1:
		parts = append(parts, "about "+strconv.FormatInt(f.Days, 10)+" active days")
	}
	if len(parts) == 1 && f.Days > 0 {
		return parts[0] + " free"
	}
	return strings.Join(parts, " and ") + ", free"
}

// lacks is what the needs the agent does not show weigh, 0 when it shows
// them all.
func (h climbHolds) lacks(needs []string) int64 {
	var w int64
	for _, n := range needs {
		w += h.needCents(n)
	}
	return w
}

// powSteps names, on each proof-of-work step, the challenge size whose one
// solution adds the cents the route counts on (C435): "cost 0" in money is
// still about 2^bits hashes, which the step now says.
func powSteps(p trust.Params, steps []ClimbStep) {
	for i := range steps {
		if steps[i].Kind != "pow" {
			continue
		}
		if bits := powBitsFor(p.Proofs["pow"], 0, steps[i].AddsCents); bits > 0 {
			steps[i].Label = fmt.Sprintf("Proof of work at bits %d (about 2^%d hashes)", bits, bits)
			steps[i].Action = strings.Replace(steps[i].Action, "BITS", strconv.FormatInt(bits, 10), 1)
		}
	}
}

func climbStepOf(w StandingWay, adds, cost int64) ClimbStep {
	return ClimbStep{Kind: w.Kind, Label: w.Label, AddsCents: adds, CostCents: cost, Needs: append([]string{}, w.Needs...), Action: w.Action}
}

// climbSearch is the cheapest set of steps over proofWays and amounts that
// closes gap (climbOf says how it weighs them), nil when none does.
func climbSearch(p trust.Params, gap int64, proofWays []StandingWay, amounts []climbAmount, holds climbHolds) []ClimbStep {
	var best []ClimbStep
	bestWeight := int64(-1)
	consider := func(steps []ClimbStep, weight int64) {
		seen := map[string]bool{}
		for _, st := range steps {
			for _, n := range st.Needs {
				if !seen[n] {
					seen[n] = true
					weight += holds.needCents(n)
				}
			}
		}
		if bestWeight < 0 || weight < bestWeight || weight == bestWeight && len(steps) < len(best) {
			best, bestWeight = append([]ClimbStep{}, steps...), weight
		}
	}
	// fill tries each order of the amounts for what a set of proofs leaves.
	used := make([]bool, len(amounts))
	var fill func(steps []ClimbStep, left, weight int64)
	fill = func(steps []ClimbStep, left, weight int64) {
		for i, a := range amounts {
			if used[i] {
				continue
			}
			adds, cost, w := a.take(p, left)
			next := append(steps[:len(steps):len(steps)], climbStepOf(a.way, adds, cost))
			if adds >= left {
				consider(next, weight+w)
				continue
			}
			used[i] = true
			fill(next, left-adds, weight+w)
			used[i] = false
		}
	}
	// pick tries every set of at most climbRouteProofs proofs.
	var pick func(from int, steps []ClimbStep, covered, weight int64)
	pick = func(from int, steps []ClimbStep, covered, weight int64) {
		if covered >= gap {
			consider(steps, weight)
			return
		}
		fill(steps, gap-covered, weight)
		if len(steps) == climbRouteProofs {
			return
		}
		for i := from; i < len(proofWays); i++ {
			w := proofWays[i]
			adds := climbCounts(p, w)
			pick(i+1, append(steps[:len(steps):len(steps)], climbStepOf(w, adds, 0)), covered+adds, weight+w.EffortMinutes)
		}
	}
	pick(0, nil, 0, 0)
	return best
}

// climbEasiest orders a route easiest first: the proofs by the needs each
// lacks alone, then the amounts in the order they fill.
func climbEasiest(steps []ClimbStep, holds climbHolds) []ClimbStep {
	sort.SliceStable(steps, func(i, j int) bool {
		ai, aj := climbAmountKind(steps[i].Kind), climbAmountKind(steps[j].Kind)
		if ai != aj {
			return aj
		}
		return !ai && holds.lacks(steps[i].Needs) < holds.lacks(steps[j].Needs)
	})
	return steps
}

// climbHoldsOf is what an agent shows from its links (any state: a claim
// shows the account or site too), its money and bond, and its world parts'
// time present.
func climbHoldsOf(links []IdentityLink, ways []StandingWay, world []trust.WorldItem) climbHolds {
	h := climbHolds{Needs: map[string]bool{}}
	for _, l := range links {
		switch l.Kind {
		case "url":
			u, err := url.Parse(l.Value)
			if err != nil {
				continue
			}
			if host := strings.ToLower(u.Hostname()); host == "github.com" || strings.HasSuffix(host, ".github.io") {
				h.Needs["github"] = true
			} else if host != "" {
				h.Needs[proofs.NeedDomain] = true
			}
		case "domain":
			h.Needs[proofs.NeedDomain] = true
		case "wallet":
			h.Needs[proofs.NeedWallet], h.Needs[proofs.NeedUSDC] = true, true
		case "npm", "pypi":
			h.Needs[proofs.NeedPackage] = true
		default:
			h.Needs[l.Kind] = true
		}
	}
	for _, w := range ways {
		if (w.Kind == "money" || w.Kind == "bond") && w.State != "none" {
			h.Needs[proofs.NeedUSDC] = true
		}
	}
	for _, it := range world {
		if it.Kind == "time_present" {
			h.TimeCents += it.Cents
		}
	}
	return h
}

// ZeroStandingNext is the one line an accept or a payout notice carries to
// a worker whose standing is 0¢ (C334): the wallet link that starts it, as
// an MCP call and a signed command. It fits an inbox entry's detail.
const ZeroStandingNext = `Standing 0¢: link a wallet to start it. MCP raise_standing action challenge, kind wallet, value ADDRESS; or standing.challenge {"schema":1,"kind":"wallet","value":ADDRESS}.`

// zeroStandingNext is ZeroStandingNext for op (a work.accept or a
// work.settle) reaching worker at 0¢ standing while trust is on; "" else.
func (s *Store) zeroStandingNext(ctx context.Context, tx *sql.Tx, op, worker string, now int64) (string, error) {
	if op != "work.accept" && op != WorkSettle || worker == "" || s.config.Features.Trust == TrustOff {
		return "", nil
	}
	p, err := s.trustParamsAt(ctx, tx, now)
	if err != nil {
		return "", err
	}
	view, _, err := trust.CurrentStanding(ctx, tx, worker, p, now)
	if err != nil || view.StandingCents > 0 {
		return "", err
	}
	return ZeroStandingNext, nil
}

// climbFor is the climb of an account from its ways, what it holds and its
// standing.
func (s *Store) climbFor(ctx context.Context, q *sql.Tx, view *trust.StandingView, ways []StandingWay, holds climbHolds, now int64) (Climb, error) {
	p, err := s.trustParamsAt(ctx, q, now)
	if err != nil {
		return Climb{}, err
	}
	return climbOf(p, view.StandingCents, climbWays(ctx, ways), holds), nil
}
