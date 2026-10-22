package trust

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"swarmmemo/internal/allowance"
)

// Rule 5 (RFC 0021, parameter version 8): one trust graph.
//
// Nodes are roots (accounts merged by attached keys, verified domains and
// shared wallet or payout addresses) plus the world node, the only source.
// The world's edge to an account is what it has paid here (§2, §7, §9):
//
//   - priced proofs, at their price rows, saturating within a proof root
//     and split between the roots that claim it; a burned proof root (§8)
//     prices 0 on any key, for good;
//   - money paid to SwarmMemo (credits bought, services paid directly), at
//     face value, once, when it comes in;
//   - payments to other accounts, only when payer and payee are independent
//     (other roots, no transfer or payment path from the payee back to the
//     payer within funded_days = H), each up to the payee's direct costs at
//     the previous run, from one budget per payee shared by every payer and
//     responder;
//   - time present: day_price for each active day (a day on which an
//     independent account with standing ≥ v_floor replied to, voted on or
//     judged the account), at most time_cap, each day backed by a responder
//     like a payment.
//
// Money and time present accumulate in the carry from run to run; a world
// edge holds while the account is active and, after grace_days without an
// active day, halves every dormant_half_life_days (§9). Returning stops the
// decay and restores nothing.
//
// Judgement edges (§2) run from a judgement's author's root to its
// subject's owners' roots, one current judgement per root and subject, with
// capacity U × (x − 50)/50 × evidence × relationship × decay(age, H) ×
// accuracy, split equally between the owners; coarse acts count as
// coarse_x; x ≤ 50 makes no edge. Accuracy (§6) is clamp(1 + 2 Σ gain /
// (n + m), 0.5, 2) from a first pass at accuracy 1.
//
// Standing is a capacity-bounded max-flow from the world (flow.go's Dinic):
// each root keeps min(world, node_cap) of its own costs less its pass share
// (version 10: what it holds above node_cap topped up to pass_share_ppm of what
// it keeps, at most its edges' capacity), and that offer flows over its
// judgement edges into the roots' sinks, its own included, raised in levels
// up to node_cap (max-min fair). Flow is conserved: what judgements deliver
// left another root's world edge.
//
// Penalties (§8) come from the detectors in every run (ring, funnel,
// shared_wallet) and from the public log's moderation and override entries:
// a member root holds 0 with no edges in or out for the duration, its money
// and time present are destroyed and its priced proof roots burn for good;
// each backer (an edge into the set within backer_edge_days) loses
// f = c / (c + U) of its standing (world edge, node_cap and out-capacity
// scaled by 1 − f); the k-th penalty on a root within escalation_days lasts
// base_days × duration_factor^(k−1) days, a backer's k-th liability costs
// min(1, backer_factor^(k−1) × f). A lift (an operator override) reverses
// an entry.
//
// The run is a pure function of its snapshot: the carry and the penalty
// log are inputs; the new carry and the new log entries are outputs, part
// of the canonical output (scripts/trust/recompute.py reproduces its
// sha256).

// Output is one run's published result. Its canonical JSON (Canonical) is
// what a verifier must reproduce byte for byte from the same Snapshot.
type Output struct {
	Schema        int64         `json:"schema"`
	Rule          string        `json:"rule"`
	AsOf          int64         `json:"as_of"`
	ParamsVersion int64         `json:"params_version"`
	ParamsSHA256  string        `json:"params_sha256"`
	CarryIn       string        `json:"carry_in_sha256"`
	Inputs        InputsSummary `json:"inputs"`
	Nodes         int64         `json:"nodes"`
	Edges         int64         `json:"edges"`
	Summary       Summary       `json:"summary"`
	Scores        []ScoreOut    `json:"scores"`
	Evidence      []EvidenceOut `json:"evidence"`
	Penalties     []PenaltyOut  `json:"penalties"`
	Carry         Carry         `json:"carry"`
	// Graph is the final flow graph, kept so per-viewer standing can be
	// computed on read (Graph.ViewerFlow); not part of the canonical output.
	Graph *Graph `json:"-"`
	// Work is the number of edge examinations; a run statistic, not output.
	Work int64 `json:"-"`
}

// InputsSummary says what the run read.
type InputsSummary struct {
	EventsSeq       int64 `json:"events_seq"`
	EndorsementsSeq int64 `json:"endorsements_seq"`
	LedgerSeq       int64 `json:"ledger_seq"`
	Accounts        int64 `json:"accounts"`
	Posts           int64 `json:"posts"`
	Endorsements    int64 `json:"endorsements"`
	Proofs          int64 `json:"proofs"`
	Transfers       int64 `json:"transfers"`
	Payments        int64 `json:"payments"`
	Acts            int64 `json:"acts"`
	Reviews         int64 `json:"reviews"`
	PenaltyEntries  int64 `json:"penalty_entries"`
}

// Summary is the run's totals: what the operator dashboard and /stats read.
type Summary struct {
	WorldCents     int64            `json:"world_cents"`
	StandingCents  int64            `json:"standing_cents"`
	OwnCents       int64            `json:"own_cents"`
	PassedCents    int64            `json:"passed_cents"`
	Top5PassedPPM  int64            `json:"top5_passed_ppm"`
	Sources        int64            `json:"sources"` // roots passing flow on
	Bands          map[string]int64 `json:"bands"`
	AboveVoteFloor int64            `json:"above_vote_floor"`
	Judgements     int64            `json:"judgements"`
	Marked         int64            `json:"marked"`
	Truncated      bool             `json:"truncated"`
	ActiveAccounts int64            `json:"active_accounts"` // with an active day in this run's days
	Penalised      int64            `json:"penalised"`       // accounts under an active member penalty
	Liable         int64            `json:"liable"`          // accounts under an active backer liability
	PenaltiesOpen  int64            `json:"penalties_open"`  // log entries active at as_of
}

// ScoreOut is one account's standing.
type ScoreOut struct {
	Account       string `json:"account"`
	Root          string `json:"root"`
	Cents         int64  `json:"cents"`
	Band          string `json:"band"`
	VoteWeightPPM int64  `json:"vote_weight_ppm"`
	Parts         Parts  `json:"parts"`
}

// Parts explain a standing: never a bare number. Cents are rounded down.
type Parts struct {
	// World is the account's own costs, each priced: its proofs, money
	// paid here, time present and independent payments.
	World       []WorldItem `json:"world"`
	WorldCents  int64       `json:"world_cents"`
	DirectCents int64       `json:"direct_cents"` // proofs and money: what backs others' payments and time present
	// The root's flow: its world edge (all its accounts), what it keeps of
	// it, what it received over judgement edges and passed on.
	RootWorldCents int64 `json:"root_world_cents"`
	OwnCents       int64 `json:"own_cents"`
	ReceivedCents  int64 `json:"received_cents"`
	PassedCents    int64 `json:"passed_cents"`
	NodeCapCents   int64 `json:"node_cap_cents"`
	// Backers are the roots whose judgement edges carried flow into this
	// root, Backs the roots this root's edges carried flow to (at most 20
	// each, largest first; *_total counts them all).
	Backers      []FlowPart `json:"backers"`
	BackersTotal int64      `json:"backers_total"`
	Backs        []FlowPart `json:"backs"`
	BacksTotal   int64      `json:"backs_total"`
	// Accuracy is the multiplier on this account's judgement edges, from
	// Judged marked judgements.
	AccuracyPPM int64 `json:"accuracy_ppm"`
	Judged      int64 `json:"judged"`
	// GraceFromDay is the day its grace counts from: its last active day,
	// or the day it first appeared; GraceDays how many days of grace are
	// left before its world edges start to halve (0: they are fading);
	// FadePPM what inactivity has left of its proofs.
	GraceFromDay int64 `json:"grace_from_day"`
	ActiveDays   int64 `json:"active_days"` // active days in this run's days
	GraceDays    int64 `json:"grace_days"`
	FadePPM      int64 `json:"fade_ppm"`
	// Penalty is the account's active penalty or liability, if any.
	Penalty *PenaltyState `json:"penalty"`
	// Burn is what a penalty on this root would burn now.
	Burn BurnPreview `json:"burn"`
}

// WorldItem is one priced own cost.
type WorldItem struct {
	Kind       string `json:"kind"` // proof, money, time_present, payments
	Source     string `json:"source"`
	Root       string `json:"root"`
	State      string `json:"state"`
	PriceCents int64  `json:"price_cents"`
	Cents      int64  `json:"cents"`
	Note       string `json:"note"`
}

// FlowPart is one judgement edge's flow, by the other root.
type FlowPart struct {
	Root     string `json:"root"`
	CapCents int64  `json:"cap_cents"`
	Cents    int64  `json:"cents"`
}

// PenaltyState is an account's active penalty: as a member (its root holds
// 0) or as a backer (it loses FractionPPM of its standing).
type PenaltyState struct {
	Entry       string `json:"entry"`
	Role        string `json:"role"` // member or backer
	FractionPPM int64  `json:"fraction_ppm"`
	Level       int64  `json:"level"`
	EndsAt      int64  `json:"ends_at"`
}

// BurnPreview is what a penalty on the account's root would burn.
type BurnPreview struct {
	OwnCents   int64          `json:"own_cents"`   // its world edge, destroyed
	ProofRoots []string       `json:"proof_roots"` // burned for good
	Backers    []BackerAtRisk `json:"backers"`     // what its backers would lose (at most 20)
}

// BackerAtRisk is one backer's liability if the root were penalised now.
type BackerAtRisk struct {
	Root        string `json:"root"`
	FractionPPM int64  `json:"fraction_ppm"`
	Cents       int64  `json:"cents"`
}

// EvidenceOut is one detector finding.
type EvidenceOut struct {
	ID              string   `json:"id"`
	Kind            string   `json:"kind"`
	Members         []string `json:"members"`
	Detail          string   `json:"detail"`
	DetectorVersion int64    `json:"detector_version"`
}

// PenaltyOut is one penalty log entry this run opened (a detector finding)
// or applied (a pending moderation or override entry): its members, level,
// duration, burned proof roots and backers' liabilities.
type PenaltyOut struct {
	ID       string      `json:"id"`
	Trigger  string      `json:"trigger"` // ring, funnel, shared_wallet, moderation, override
	Opened   bool        `json:"opened"`  // opened by this run's detectors (else a pending entry applied)
	Members  []string    `json:"members"`
	Level    int64       `json:"level"`
	StartsAt int64       `json:"starts_at"`
	EndsAt   int64       `json:"ends_at"`
	Burned   []string    `json:"burned"`
	Backers  []BackerOut `json:"backers"`
	Evidence string      `json:"evidence"`
	// BurnedCents is the members' world edge the entry destroyed in this run.
	BurnedCents int64 `json:"burned_cents"`
}

// BackerOut is one backer's liability under an entry.
type BackerOut struct {
	Account     string `json:"account"`
	CapCents    int64  `json:"cap_cents"`
	Level       int64  `json:"level"`
	FractionPPM int64  `json:"fraction_ppm"`
	LostCents   int64  `json:"lost_cents"`
}

// Canonical is the output's canonical JSON.
func (o Output) Canonical() []byte { return Canonical(o) }

const day = 86400

// mc is the run's unit: a thousandth of a cent.
const mc = 1000

func dayOf(t int64) int64 {
	if t < 0 {
		return -((-t + day - 1) / day)
	}
	return t / day
}

// uf is a union-find over strings.
type uf map[string]string

func (u uf) find(x string) string {
	for {
		p, ok := u[x]
		if !ok || p == x {
			return x
		}
		if gp := u[p]; gp != "" && gp != p {
			u[x] = gp
		}
		x = p
	}
}

func (u uf) union(a, b string) {
	ra, rb := u.find(a), u.find(b)
	if ra == rb {
		return
	}
	if rb < ra {
		ra, rb = rb, ra
	}
	u[ra] = ra
	u[rb] = ra
}

// DomainRoot is domainRoot over a suffix list (Params.DomainSuffixes).
func DomainRoot(domain string, suffixes []string) string {
	set := make(map[string]bool, len(suffixes))
	for _, s := range suffixes {
		set[s] = true
	}
	return domainRoot(domain, set)
}

// domainRoot is "domain:" + the registrable domain: one label under the
// longest listed multi-label suffix, else the last two labels.
func domainRoot(domain string, suffixes map[string]bool) string {
	labels := strings.Split(strings.ToLower(strings.TrimSuffix(domain, ".")), ".")
	keep := 2
	for i := 1; i < len(labels)-1; i++ {
		if suffixes[strings.Join(labels[i:], ".")] {
			keep = len(labels) - i + 1
			break
		}
	}
	if keep > len(labels) {
		keep = len(labels)
	}
	return "domain:" + strings.Join(labels[len(labels)-keep:], ".")
}

// endorsementLess orders endorsement records by seq, then by content, so
// that even duplicate sequence numbers sort the same way everywhere.
func endorsementLess(a, b *Record) bool {
	if a.Seq != b.Seq {
		return a.Seq < b.Seq
	}
	if a.CreatedAt != b.CreatedAt {
		return a.CreatedAt < b.CreatedAt
	}
	if a.Kind != b.Kind {
		return a.Kind < b.Kind
	}
	if a.Voter != b.Voter {
		return a.Voter < b.Voter
	}
	if a.Target != b.Target {
		return a.Target < b.Target
	}
	if a.MessageID != b.MessageID {
		return a.MessageID < b.MessageID
	}
	return a.Value < b.Value
}

// logEntry is one penalty log entry the run read.
type logEntry struct {
	id, trigger, evidence string
	members               []string
	start, end, level     int64
	pending, lifted       bool
	burned                []string
	liabilities           []Record
}

func (e *logEntry) activeAt(t int64) bool {
	return !e.lifted && !e.pending && e.start <= t && t < e.end
}

// readLog assembles the penalty log's entries from their records.
func readLog(snap Snapshot) (map[string]*logEntry, []string, error) {
	log := map[string]*logEntry{}
	for _, r := range sortRecords(snap.Penalties) {
		if r.ID == "" || r.Account == "" {
			return nil, nil, fmt.Errorf("trust input: a penalty record needs an id and an account")
		}
		e := log[r.ID]
		if e == nil {
			e = &logEntry{id: r.ID, trigger: r.Kind, evidence: r.Evidence, start: r.CreatedAt, end: r.EndsAt, level: r.Value, pending: r.State == "pending"}
			log[r.ID] = e
		} else if e.trigger != r.Kind || e.start != r.CreatedAt || e.end != r.EndsAt || e.level != r.Value || e.pending != (r.State == "pending") || e.evidence != r.Evidence {
			return nil, nil, fmt.Errorf("trust input: penalty entry %q has members that disagree", r.ID)
		}
		switch r.Kind {
		case "ring", "funnel", "shared_wallet", "moderation", "override":
		default:
			return nil, nil, fmt.Errorf("trust input: penalty entry %q has an unknown trigger %q", r.ID, r.Kind)
		}
		e.members = append(e.members, r.Account)
	}
	for _, r := range sortRecords(snap.Burns) {
		if e := log[r.ID]; e != nil && r.Root != "" {
			e.burned = append(e.burned, r.Root)
		}
	}
	for _, r := range sortRecords(snap.Liabilities) {
		if e := log[r.ID]; e != nil && r.Account != "" {
			e.liabilities = append(e.liabilities, r)
		}
	}
	for _, r := range sortRecords(snap.Lifts) {
		if e := log[r.ID]; e != nil && r.CreatedAt <= snap.Meta.AsOf {
			e.lifted = true
		}
	}
	ids := make([]string, 0, len(log))
	for id := range log {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return log, ids, nil
}

// carryIn is the previous run's carry, by account.
type carryIn struct {
	asOf     int64
	accounts map[string]CarryAccount
}

func carryFromRecords(list []Record) (*carryIn, error) {
	if len(list) == 0 {
		return nil, nil
	}
	c := &carryIn{accounts: map[string]CarryAccount{}}
	runs := 0
	for _, r := range sortRecords(list) {
		switch r.Kind {
		case "run":
			runs++
			c.asOf = r.AsOf
		case "world":
			if r.Account == "" || r.Amount < 0 || r.Time < 0 || r.Backed < 0 || r.Direct < 0 || r.Standing < 0 || r.FractionPPM < 0 || r.FractionPPM > 1e6 {
				return nil, fmt.Errorf("trust input: carry world record for %q is out of range", r.Account)
			}
			if _, dup := c.accounts[r.Account]; dup {
				return nil, fmt.Errorf("trust input: carry world record for %q is repeated", r.Account)
			}
			if r.Amount > 1<<50 || r.Time > 1<<50 || r.Backed > 1<<50 || r.Direct > 1<<40 || r.Standing > 1<<40 {
				return nil, fmt.Errorf("trust input: carry world record for %q is out of range", r.Account)
			}
			c.accounts[r.Account] = CarryAccount{Account: r.Account, Money: r.Amount, Time: r.Time, FadePPM: r.FractionPPM, LastActive: r.LastActive,
				Direct: r.Direct, Standing: r.Standing, Backed: r.Backed}
		default:
			return nil, fmt.Errorf("trust input: unknown carry kind %q", r.Kind)
		}
	}
	if runs != 1 {
		return nil, fmt.Errorf("trust input: the carry needs one run record, not %d", runs)
	}
	return c, nil
}

// Compute runs the trust module on one snapshot. It is a pure function of
// the snapshot: record order does not matter, and nothing reads the clock
// except to stop at max_seconds.
func Compute(ctx context.Context, snap Snapshot) (Output, error) {
	p := snap.Params
	if p.Version < UnifiedVersion {
		return Output{}, ErrRetiredVersion{p.Version}
	}
	if err := p.Validate(); err != nil {
		return Output{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(p.MaxSeconds)*time.Second)
	defer cancel()
	r := &run{p: p, snap: snap, asOf: snap.Meta.AsOf, cv: curves{}}
	return r.compute(ctx)
}

// run is one computation's state.
type run struct {
	p    Params
	snap Snapshot
	asOf int64
	D    int64
	cv   curves

	accounts []string
	known    map[string]bool
	base     uf // keys and verified domains
	full     uf // and live wallet or payout addresses
	label    map[string]string
	rootOf   func(string) string

	log    map[string]*logEntry
	logIDs []string

	work int64
}

func (r *run) compute(ctx context.Context) (Output, error) {
	p, snap, asOf := r.p, r.snap, r.asOf
	D := dayOf(asOf)
	r.D = D
	H := p.HalfLifeDays
	ws := asOf - p.WindowDays*day
	U := p.UnitCents * mc
	nodeCap := p.NodeCapCents * mc

	carry, err := carryFromRecords(snap.Carry)
	if err != nil {
		return Output{}, err
	}
	if carry != nil && carry.asOf > asOf {
		return Output{}, fmt.Errorf("trust input: the carry is as of %d, after this run's %d", carry.asOf, asOf)
	}
	carryIn := ""
	if len(snap.Carry) > 0 {
		carryIn = sha256Hex(Canonical(sortRecords(snap.Carry)))
	}
	prevAsOf := ws
	if carry != nil {
		prevAsOf = max(carry.asOf, asOf-3650*day)
	}
	prevD := dayOf(prevAsOf)

	r.log, r.logIDs, err = readLog(snap)
	if err != nil {
		return Output{}, err
	}

	// Accounts seen anywhere.
	r.known = map[string]bool{}
	see := func(a string) {
		if a != "" {
			r.known[a] = true
		}
	}
	firstSeen := map[string]int64{}
	for _, x := range snap.Accounts {
		see(x.Account)
		if x.FirstSeen > 0 && (firstSeen[x.Account] == 0 || x.FirstSeen < firstSeen[x.Account]) {
			firstSeen[x.Account] = x.FirstSeen
		}
	}
	for _, x := range snap.Posts {
		see(x.Account)
		see(x.ReplyToAccount)
	}
	for _, x := range snap.Endorsements {
		see(x.Voter)
		see(x.Target)
	}
	for _, x := range snap.Proofs {
		see(x.Account)
	}
	for _, x := range snap.Payments {
		see(x.Account)
		see(x.To)
	}
	for _, x := range snap.Acts {
		see(x.From)
		see(x.To)
	}
	for _, x := range snap.Transfers {
		see(x.From)
		see(x.To)
	}
	for _, x := range snap.Claims {
		see(x.Account)
	}
	for _, x := range snap.Reviews {
		see(x.Account)
		if strings.HasPrefix(x.Target, "agent:") {
			see(x.Target[len("agent:"):])
		}
	}
	for _, x := range snap.Owners {
		see(x.Account)
	}
	if carry != nil {
		for a := range carry.accounts {
			see(a)
		}
	}
	for _, id := range r.logIDs {
		for _, m := range r.log[id].members {
			see(m)
		}
	}

	// Breakers and pause-new-keys: such an account's judgements make no
	// edge and it is no responder. A breaker holds until its trust_until,
	// or for version 11 its reason's breaker_trust_days if sooner (§2.2).
	reset := map[string]bool{}
	for _, x := range snap.Breakers {
		if x.StartedAt <= asOf && p.BreakerUntil(x) > asOf {
			reset[x.Account] = true
		}
	}
	if since := snap.Meta.PauseNewKeysSince; since > 0 {
		for a, t := range firstSeen {
			if t > since {
				reset[a] = true
			}
		}
	}

	// Burned proof roots: every entry not lifted burns its roots for good.
	burned := map[string]bool{}
	for _, id := range r.logIDs {
		if e := r.log[id]; !e.lifted {
			for _, b := range e.burned {
				burned[b] = true
			}
		}
	}

	// Roots.
	suffixes := map[string]bool{}
	for _, s := range p.DomainSuffixes {
		suffixes[s] = true
	}
	fresh := asOf - p.ProofFreshDays*day
	counts := func(x Record) bool {
		if x.CreatedAt > asOf {
			return false
		}
		switch {
		case x.Kind == "domain" || p.Proofs[x.Kind].Assess != "":
			return x.State == "verified" && x.CheckedAt >= fresh && x.CheckedAt <= asOf
		case x.Kind == "ed25519":
			return x.State == "proof_attached" || x.State == "verified"
		}
		return x.State == "verified"
	}
	proofs := sortRecords(snap.Proofs)
	r.base, r.full = uf{}, uf{}
	for _, x := range proofs {
		if !counts(x) {
			continue
		}
		switch x.Kind {
		case "domain":
			d := domainRoot(x.LinkValue, suffixes)
			r.base.union(x.Account, d)
			r.full.union(x.Account, d)
		case "ed25519":
			if x.LinkAccount != "" {
				r.base.union(x.Account, x.LinkAccount)
				r.full.union(x.Account, x.LinkAccount)
			}
		case "wallet":
			if x.Root != "" && !burned[x.Root] {
				r.full.union(x.Account, x.Root)
			}
		}
	}
	payments := sortRecords(snap.Payments)
	for _, x := range payments {
		if x.To != "" && x.LinkValue != "" && !burned[x.LinkValue] && x.CreatedAt < asOf {
			r.full.union(x.To, x.LinkValue)
		}
	}
	r.label = labels(r.full)
	r.rootOf = func(a string) string {
		if _, ok := r.full[a]; !ok {
			return a
		}
		return r.label[r.full.find(a)]
	}
	baseLabel := labels(r.base)
	baseRoot := func(a string) string {
		if _, ok := r.base[a]; !ok {
			return a
		}
		return baseLabel[r.base.find(a)]
	}

	// Funded pairs (a transfer or payment either way within funded_days = H)
	// and the directed money graph for transfer paths.
	fundedFrom := asOf - H*day
	funded := map[[2]string]bool{}
	moneyOut := map[string][]string{}
	link := func(from, to string, at int64) {
		if from == "" || to == "" || from == to || at < fundedFrom || at >= asOf {
			return
		}
		funded[[2]string{from, to}], funded[[2]string{to, from}] = true, true
		moneyOut[from] = append(moneyOut[from], to)
	}
	for _, x := range snap.Transfers {
		if x.Amount > 0 {
			link(x.From, x.To, x.CreatedAt)
		}
	}
	for _, x := range payments {
		if x.Amount > 0 {
			link(x.Account, x.To, x.CreatedAt)
		}
	}
	for a := range moneyOut {
		sort.Strings(moneyOut[a])
	}
	indep := func(a, b string) bool { return PublicIndependent(a, b, r.rootOf, funded) }

	// Active penalties at as-of (from the log; this run's findings are
	// added below).
	member := map[string]*logEntry{} // full root → entry
	liable := map[string]PenaltyState{}
	applyLog := func(e *logEntry) {
		for _, m := range e.members {
			if root := r.rootOf(m); member[root] == nil || e.id < member[root].id {
				member[root] = e
			}
		}
		for _, l := range e.liabilities {
			if l.CreatedAt <= asOf && asOf < l.EndsAt {
				root := r.rootOf(l.Account)
				if cur, ok := liable[root]; !ok || l.FractionPPM > cur.FractionPPM {
					liable[root] = PenaltyState{Entry: e.id, Role: "backer", FractionPPM: min(1e6, l.FractionPPM), Level: l.Value, EndsAt: l.EndsAt}
				}
			}
		}
	}
	for _, id := range r.logIDs {
		if e := r.log[id]; e.activeAt(asOf) {
			applyLog(e)
		}
	}
	penalised := func(a string) bool { return member[r.rootOf(a)] != nil }

	// Proofs: each priced proof root counts once, split between the roots
	// that claim it; within a root, its best claim counts.
	type claim struct {
		account string
		item    WorldItem
		price   int64 // cents
		value   int64 // cents: the price without a capped row's fallback floor
	}
	var claims []claim
	for _, x := range proofs {
		price := p.Proofs[x.Kind]
		if x.Kind != "domain" && price.Assess == "" {
			continue // control, not cost (ed25519, board, url, nostr)
		}
		it := WorldItem{Kind: "proof", Source: x.Kind, State: x.State}
		switch {
		case x.Kind == "domain":
			it.Root = domainRoot(x.LinkValue, suffixes)
		case x.Root != "":
			it.Root = x.Root
		default:
			it.Root = x.Kind + ":" + x.LinkValue
		}
		var cents, value int64
		switch {
		case !counts(x):
			it.Note = "not counted: not verified within proof_fresh_days"
		case burned[it.Root]:
			it.State, it.Note = "burned", "burned by a penalty: prices 0 on any key"
		case x.Kind == "domain":
			cents = DomainContribution(price, D-dayOf(x.RegisteredAt), x.RegisteredAt, x.Rank)
			if x.RegisteredAt <= 0 && x.Rank <= 0 {
				it.Note = "registration age and rank not yet fetched: priced at the domain row's fallback"
			} else {
				value = cents // priced by its signals: no floor to drop
			}
		default:
			cents, value = AssessedContribution(price, x.Assessed), AssessedValue(price, x.Assessed)
		}
		it.PriceCents = cents
		claims = append(claims, claim{x.Account, it, cents, value})
	}
	// A capped row's fallback floor prices control of a key, which is free
	// to make again: from version 12 (FloorOnceVersion), per (kind, node
	// root) only the best claim keeps it, and the others price at their
	// assessed value (C492). N fresh wallets on one root count the floor
	// once; real balances still stack. From version 13
	// (DomainFloorOnceVersion) a domain priced at its row's fallback (age
	// and rank unknown, value 0) takes the same rule (C515); a domain
	// priced by its signals still stacks. Versions up to 11 price each
	// claim with its floor, and up to 12 each domain, as their published
	// runs did.
	floorOf := map[[2]string]int{} // (kind, node root) → claim index
	for i, c := range claims {
		row := p.Proofs[c.item.Source]
		capped := p.Version >= FloorOnceVersion && row.Assess == AssessCapped && row.FallbackCents > 0
		domain := p.Version >= DomainFloorOnceVersion && c.item.Source == "domain" && c.value < c.price
		if c.price <= 0 || !capped && !domain {
			continue
		}
		k := [2]string{c.item.Source, r.rootOf(c.account)}
		// The highest price keeps the floor; at equal price the higher
		// value (where the floor adds least), then the lower account.
		if j, ok := floorOf[k]; !ok || c.price > claims[j].price || c.price == claims[j].price &&
			(c.value > claims[j].value || c.value == claims[j].value && c.account < claims[j].account) {
			floorOf[k] = i
		}
	}
	for i := range claims {
		c := &claims[i]
		j, ok := floorOf[[2]string{c.item.Source, r.rootOf(c.account)}]
		if !ok || j == i || c.value >= c.price {
			continue
		}
		c.price, c.item.PriceCents = c.value, c.value
		c.item.Note = "fallback counted once per root: on " + claims[j].account
	}
	// Per proof root: the claiming roots and each root's best claim.
	bestOf := map[[2]string]int{} // (proof root, node root) → claim index
	claimants := map[string]map[string]bool{}
	for i, c := range claims {
		if c.price <= 0 {
			continue
		}
		k := [2]string{c.item.Root, r.rootOf(c.account)}
		if j, ok := bestOf[k]; !ok || c.price > claims[j].price || c.price == claims[j].price && c.account < claims[j].account {
			bestOf[k] = i
		}
		if claimants[c.item.Root] == nil {
			claimants[c.item.Root] = map[string]bool{}
		}
		claimants[c.item.Root][r.rootOf(c.account)] = true
	}
	proofMC := map[string]int64{} // account → counted proofs (mc), before fade
	items := map[string][]WorldItem{}
	proofRootsOf := map[string][]string{} // account → its counted proof roots
	for i, c := range claims {
		it := c.item
		if c.price > 0 {
			proofRootsOf[c.account] = append(proofRootsOf[c.account], it.Root)
			k := [2]string{it.Root, r.rootOf(c.account)}
			if bestOf[k] == i {
				n := int64(len(claimants[it.Root]))
				share := c.price * mc / n
				proofMC[c.account] += share
				it.Cents = share / mc
				if n > 1 {
					it.Note = "shared with " + strconv.FormatInt(n-1, 10) + " other root(s): split"
				}
			} else {
				it.Note = "saturated by " + claims[bestOf[k]].item.Source + " on " + claims[bestOf[k]].account
			}
		}
		items[c.account] = append(items[c.account], it)
	}

	// Prior standing and direct costs: the previous run's, and at least
	// this run's own costs (proofs held now, faded as the carry left them,
	// and money paid to SwarmMemo since the carry; a first run counts all
	// of it). Own costs never depend on standing, so the bootstrap is not
	// circular: a carry from a run that priced everything at 0 (C320c's
	// dry run) does not hold the next run at 0 for another run (§9).
	moneyAll := map[string]int64{}
	for _, x := range payments {
		if x.To == "" && x.Amount > 0 && x.CreatedAt < asOf && (carry == nil || x.CreatedAt >= prevAsOf) {
			moneyAll[x.Account] += min(x.Amount, 1<<40) * mc
		}
	}
	ownDirect := func(a string) int64 { // mc
		if carry != nil {
			if c, ok := carry.accounts[a]; ok {
				return mulDiv(proofMC[a], c.FadePPM, 1e6) + moneyAll[a]
			}
		}
		return proofMC[a] + moneyAll[a]
	}
	priorDirect := func(a string) int64 { // mc
		if carry != nil {
			return max(carry.accounts[a].Direct*mc, ownDirect(a))
		}
		return ownDirect(a)
	}

	// Budgets: a payee's or responder's direct costs back at most that much
	// outstanding credit (payments recomputed each run over funded_days;
	// time present carried, its backing decaying with H).
	span := max(0, D-prevD)
	backed := map[string]int64{}
	if carry != nil {
		for a, c := range carry.accounts {
			if c.Backed > 0 {
				backed[a] = mulDiv(c.Backed, r.cv.decay(p.DayFactorPPM, span), 1e6)
			}
		}
	}
	used := map[string]int64{} // this run's payment credits backed, by payee
	budget := func(b string) int64 { return max(0, priorDirect(b)-backed[b]-used[b]) }
	// A settled USDC payment (paid on chain to the payee's payout address,
	// the transaction verified) is backed by at least the wallet row's
	// fallback: the payee named, signed and was paid at that address.
	settledFloor := p.Proofs["wallet"].FallbackCents * mc
	settledBudget := func(b string) int64 { return max(0, max(priorDirect(b), settledFloor)-backed[b]-used[b]) }

	// Payments to other accounts, within funded_days, when payer and payee
	// are independent (§7). Settled USDC (work rewards, paid offering
	// calls) is money that left the payer: it counts as the payer's own
	// cost (paidOut, like money paid here, and it backs the time present of
	// those it answers), up to the payee's settled budget. Credit paid to an
	// account (x402 calls to an address it topped up from) counts as a
	// payment credit (paid), up to the payee's direct costs.
	reaches := map[string]map[string]bool{}
	reach := func(from string) map[string]bool {
		if m, ok := reaches[from]; ok {
			return m
		}
		m := map[string]bool{from: true}
		queue := []string{from}
		for len(queue) > 0 {
			x := queue[0]
			queue = queue[1:]
			for _, y := range moneyOut[x] {
				if !m[y] {
					m[y] = true
					queue = append(queue, y)
				}
			}
		}
		reaches[from] = m
		return m
	}
	paid := map[string]int64{} // payer → credited (mc)
	paidN := map[string]int64{}
	paidOut := map[string]int64{} // payer → settled USDC credited (mc)
	paidOutN := map[string]int64{}
	for _, x := range payments {
		if x.To == "" || x.Amount <= 0 || x.CreatedAt < fundedFrom || x.CreatedAt >= asOf {
			continue
		}
		a, b := x.Account, x.To
		if a == b || r.rootOf(a) == r.rootOf(b) || penalised(a) || penalised(b) || reach(b)[a] {
			continue
		}
		settled := SettledPaymentKind(x.Kind)
		room := budget(b)
		if settled {
			room = settledBudget(b)
		}
		credit := min(min(x.Amount, 1<<40)*mc, room)
		if credit <= 0 {
			continue
		}
		used[b] += credit
		if settled {
			paidOut[a] += credit
			paidOutN[a]++
		} else {
			paid[a] += credit
			paidN[a]++
		}
	}

	priorStanding := func(a string) int64 { // cents
		own := min(ownDirect(a)+paidOut[a], nodeCap) / mc
		if carry != nil {
			return max(carry.accounts[a].Standing, own)
		}
		return own
	}

	// Activity: responses in [prevAsOf, asOf) by independent accounts with
	// standing ≥ v_floor.
	type response struct {
		day       int64
		responder string
	}
	responses := map[string][]response{}
	respond := func(by, to string, at int64) {
		if by == "" || to == "" || at < prevAsOf || at >= asOf || reset[by] || penalised(by) || !indep(by, to) || priorStanding(by) < p.VFloorCents {
			return
		}
		responses[to] = append(responses[to], response{dayOf(at), by})
	}
	for _, x := range snap.Posts {
		if x.ReplyToAccount != "" {
			respond(x.Account, x.ReplyToAccount, x.CreatedAt)
		}
	}
	for _, x := range snap.Endorsements {
		if (x.Kind == "vote" && x.Value != 0) || (x.Kind == "vouch" && x.Value == 1) {
			respond(x.Voter, x.Target, x.CreatedAt)
		}
	}
	for _, x := range snap.Acts {
		respond(x.From, x.To, x.CreatedAt)
	}
	reviewOwners := map[string][]string{}
	for _, x := range sortRecords(snap.Owners) {
		reviewOwners[x.Target] = append(reviewOwners[x.Target], x.Account)
	}
	for _, x := range snap.Reviews {
		owners := reviewOwners[x.Target]
		if strings.HasPrefix(x.Target, "agent:") {
			owners = append(owners, x.Target[len("agent:"):])
		}
		for _, o := range owners {
			respond(x.Account, o, x.CreatedAt)
		}
	}
	activeOn := map[int64][]string{} // day → accounts active that day
	respondersOf := map[[2]string][]string{}
	for a, list := range responses {
		days := map[int64]map[string]bool{}
		for _, x := range list {
			if days[x.day] == nil {
				days[x.day] = map[string]bool{}
			}
			days[x.day][x.responder] = true
		}
		for d, set := range days {
			activeOn[d] = append(activeOn[d], a)
			var rs []string
			for x := range set {
				rs = append(rs, x)
			}
			sort.Strings(rs)
			respondersOf[[2]string{a, strconv.FormatInt(d, 10)}] = rs
		}
	}
	for d := range activeOn {
		sort.Strings(activeOn[d])
	}

	// World accumulators, day by day over this run's days.
	type world struct {
		money, time, fade, last, active int64
	}
	ws2 := map[string]*world{}
	moneyIn := map[string]map[int64]int64{}
	for _, x := range payments {
		if x.To != "" || x.Amount <= 0 || x.CreatedAt >= asOf || (carry != nil && x.CreatedAt < prevAsOf) {
			continue
		}
		d := max(prevD, dayOf(x.CreatedAt))
		if moneyIn[x.Account] == nil {
			moneyIn[x.Account] = map[int64]int64{}
		}
		moneyIn[x.Account][d] += min(x.Amount, 1<<40) * mc
	}
	firstCost := map[string]int64{}
	cost := func(a string, at int64) {
		if d := dayOf(at); at < asOf && (firstCost[a] == 0 || d < firstCost[a]) {
			firstCost[a] = d
		}
	}
	for _, x := range payments {
		if x.To == "" && x.Amount > 0 {
			cost(x.Account, x.CreatedAt)
		}
	}
	for _, x := range proofs {
		if p.Proofs[x.Kind].Assess != "" && counts(x) {
			cost(x.Account, x.CreatedAt)
		}
	}
	r.accounts = make([]string, 0, len(r.known))
	for a := range r.known {
		r.accounts = append(r.accounts, a)
	}
	sort.Strings(r.accounts)
	for _, a := range r.accounts {
		// Without a carry, an account's grace counts from its first
		// appearance in the run's days: first seen, or its first cost.
		w := &world{fade: 1e6, last: max(prevD, firstCost[a])}
		if fs := firstSeen[a]; fs > 0 {
			w.last = max(w.last, dayOf(fs))
		}
		if carry != nil {
			if c, ok := carry.accounts[a]; ok {
				w.money, w.time, w.fade, w.last = c.Money, c.Time, c.FadePPM, c.LastActive
			}
		}
		ws2[a] = w
	}
	f := p.DormantDayFactorPPM
	dayPrice, timeCap := p.DayPriceCents*mc, p.TimeCapCents*mc
	newBacked := map[string]int64{}
	for d := prevD; d < D; d++ {
		for _, a := range r.accounts {
			w := ws2[a]
			if d-w.last > p.GraceDays {
				w.money, w.time, w.fade = mulDiv(w.money, f, 1e6), mulDiv(w.time, f, 1e6), mulDiv(w.fade, f, 1e6)
			}
			w.money += moneyIn[a][d]
		}
		for _, a := range activeOn[d] {
			w := ws2[a]
			w.last, w.active = d, w.active+1
			if w.time+dayPrice > timeCap || dayPrice <= 0 {
				continue
			}
			for _, by := range respondersOf[[2]string{a, strconv.FormatInt(d, 10)}] {
				if budget(by)+paidOut[by]-newBacked[by] >= dayPrice {
					newBacked[by] += dayPrice
					w.time += dayPrice
					break
				}
			}
		}
	}

	// Each account's world edge (mc); a member's is 0, and its money and
	// time present are destroyed.
	worldMC := map[string]int64{}
	directMC := map[string]int64{}
	for _, a := range r.accounts {
		w := ws2[a]
		if penalised(a) {
			w.money, w.time = 0, 0
			continue
		}
		pr := mulDiv(proofMC[a], w.fade, 1e6)
		directMC[a] = pr + w.money
		worldMC[a] = pr + w.money + w.time + paid[a] + paidOut[a]
	}

	// Judgements and the graph.
	set := collectJudgements(p, snap, asOf, ws, reset, r.rootOf)
	g := r.newGraph(worldMC, member, liable)
	acc1 := func(string) int64 { return 1e6 }
	g.setEdges(r, set, acc1, member, liable)
	res1, err := g.flow(ctx, nil, p.MaxWork, r.work)
	r.work = res1.work
	if err != nil {
		return Output{Work: r.work}, err
	}
	s1 := func(a string) int64 {
		if i, ok := g.Index[r.rootOf(a)]; ok {
			return res1.Standing[i] / mc
		}
		return 0
	}

	// Accuracy (§6), from the first pass.
	v1 := map[string]int64{}
	am := markAccuracy(accuracyInput{p: p, set: set, asOf: asOf, maxWork: p.MaxWork,
		vOf: func(a string) int64 {
			v, ok := v1[a]
			if !ok {
				v = p.VoteWeight(s1(a))
				v1[a] = v
			}
			return v
		},
		penalty:  penalised,
		indep:    indep,
		decayDay: func(days int64) int64 { return r.cv.decay(p.DayFactorPPM, days) }})
	r.work += am.work
	accuracy := func(a string) int64 { return AccuracyPPM(am.gain[a], am.marked[a], p.MinJudges) }
	g.setEdges(r, set, accuracy, member, liable)

	// Detectors on the final graph, before this run's findings apply.
	evidence := r.detect(g, set, payments, funded, baseRoot)
	var penalties []PenaltyOut
	opened := map[string]bool{}
	escalation := func(roots map[string]bool, isBacker bool) int64 {
		var k int64
		since := asOf - p.Penalty.EscalationDays*day
		for _, id := range r.logIDs {
			e := r.log[id]
			if e.lifted || e.pending || e.start <= since || e.start > asOf {
				continue
			}
			if isBacker {
				for _, l := range e.liabilities {
					if roots[r.rootOf(l.Account)] {
						k++
						break
					}
				}
				continue
			}
			for _, m := range e.members {
				if roots[r.rootOf(m)] {
					k++
					break
				}
			}
		}
		return min(p.Penalty.MaxLevel, k+1)
	}
	duration := func(k int64) int64 {
		d := p.Penalty.BaseDays
		for i := int64(1); i < k && d < 3650; i++ {
			d *= p.Penalty.DurationFactor
		}
		return min(d, 3650) * day
	}
	// open applies an entry found or pending in this run: its members, burns
	// and backers.
	open := func(id, trigger, evidenceRef string, members []string, level, start, end int64, isNew bool) PenaltyOut {
		roots := map[string]bool{}
		for _, m := range members {
			roots[r.rootOf(m)] = true
		}
		if level <= 0 {
			level = escalation(roots, false)
		}
		if end <= 0 {
			end = start + duration(level)
		}
		out := PenaltyOut{ID: id, Trigger: trigger, Opened: isNew, Members: members, Level: level, StartsAt: start, EndsAt: end, Evidence: evidenceRef,
			Burned: []string{}, Backers: []BackerOut{}}
		burnSet := map[string]bool{}
		for _, a := range r.accounts {
			if roots[r.rootOf(a)] {
				out.BurnedCents += worldMC[a] / mc
				for _, pr := range proofRootsOf[a] {
					burnSet[pr] = true
				}
			}
		}
		for pr := range burnSet {
			out.Burned = append(out.Burned, pr)
		}
		sort.Strings(out.Burned)
		// Backers: authors outside the set of judgement edges into it made
		// within backer_edge_days, c their edges' capacity.
		from := asOf - p.Penalty.BackerEdgeDays*day
		c := g.recentCapInto(roots, from)
		backers := make([]string, 0, len(c))
		for a := range c {
			backers = append(backers, a)
		}
		sort.Strings(backers)
		for _, a := range backers {
			fPPM := mulDiv(c[a], 1e6, c[a]+U)
			k := escalation(map[string]bool{r.rootOf(a): true}, true)
			frac := fPPM
			for i := int64(1); i < k && frac < 1e6; i++ {
				frac *= p.Penalty.BackerFactor
			}
			frac = min(1e6, frac)
			if frac <= 0 {
				continue
			}
			out.Backers = append(out.Backers, BackerOut{Account: a, CapCents: c[a] / mc, Level: k, FractionPPM: frac})
		}
		return out
	}
	// Pending entries (moderation, override) apply first; a detector's
	// finding opens an entry only for members not already penalised.
	applying := map[string]bool{}
	for _, id := range r.logIDs {
		e := r.log[id]
		if !e.pending || e.lifted || e.start > asOf {
			continue
		}
		penalties = append(penalties, open(e.id, e.trigger, e.evidence, e.members, e.level, e.start, e.end, false))
		for _, m := range e.members {
			applying[r.rootOf(m)] = true
		}
	}
	for _, ev := range evidence {
		var members []string
		for _, m := range ev.Members {
			if !penalised(m) && !applying[r.rootOf(m)] {
				members = append(members, m)
			}
		}
		if len(members) == 0 || opened[ev.ID] || r.log[ev.ID] != nil {
			continue
		}
		opened[ev.ID] = true
		penalties = append(penalties, open(ev.ID, ev.Kind, ev.Detail, members, 0, asOf, 0, true))
	}
	sort.Slice(penalties, func(i, j int) bool { return penalties[i].ID < penalties[j].ID })
	// Apply them: members to 0 (and burned, destroyed), backers scaled. The
	// flow before them says what each backer lost.
	var pre flowResult
	if len(penalties) > 0 {
		if pre, err = g.flow(ctx, nil, p.MaxWork, r.work); err != nil {
			return Output{Work: pre.work}, err
		}
		r.work = pre.work
		for _, pen := range penalties {
			if pen.StartsAt > asOf || asOf >= pen.EndsAt {
				continue
			}
			e := &logEntry{id: pen.ID, members: pen.Members}
			for _, b := range pen.Backers {
				e.liabilities = append(e.liabilities, Record{Account: b.Account, FractionPPM: b.FractionPPM, CreatedAt: pen.StartsAt, EndsAt: pen.EndsAt, Value: b.Level})
			}
			applyLog(e)
		}
		for _, a := range r.accounts {
			if penalised(a) {
				ws2[a].money, ws2[a].time = 0, 0
				worldMC[a], directMC[a] = 0, 0
			}
		}
		g = r.newGraph(worldMC, member, liable)
		g.setEdges(r, set, accuracy, member, liable)
	}
	res, err := g.flow(ctx, nil, p.MaxWork, r.work)
	r.work = res.work
	if err != nil {
		return Output{Work: r.work}, err
	}
	// What each backer lost (the node sets of both flows are the accounts'
	// roots, so their indices agree).
	for i := range penalties {
		for j := range penalties[i].Backers {
			b := &penalties[i].Backers[j]
			if k, ok := g.Index[r.rootOf(b.Account)]; ok {
				b.LostCents = max(0, pre.Standing[k]-res.Standing[k]) / mc
			}
		}
	}

	// Scores.
	sum := Summary{Bands: map[string]int64{}, Judgements: am.judged, Marked: sumValues(am.marked), Truncated: am.truncated}
	for b := allowance.BandSigned; b <= allowance.BandTrusted; b++ {
		sum.Bands[b.Name()] = 0
	}
	for _, id := range r.logIDs {
		if r.log[id].activeAt(asOf) {
			sum.PenaltiesOpen++
		}
	}
	for _, pen := range penalties {
		if pen.StartsAt <= asOf && asOf < pen.EndsAt {
			sum.PenaltiesOpen++
		}
	}
	var passed []int64
	for i := range g.Labels {
		sum.WorldCents += g.World[i] / mc
		sum.StandingCents += res.Standing[i] / mc
		sum.OwnCents += res.Own[i] / mc
		sum.PassedCents += res.Passed[i] / mc
		if res.Passed[i] > 0 {
			sum.Sources++
			passed = append(passed, res.Passed[i])
		}
	}
	sort.Slice(passed, func(i, j int) bool { return passed[i] > passed[j] })
	var top, total int64
	for i, x := range passed {
		total += x
		if i < 5 {
			top += x
		}
	}
	if total > 0 {
		sum.Top5PassedPPM = mulDiv(top, 1e6, total)
	}
	inFlows, outFlows := g.edgeFlows(res)
	scores := make([]ScoreOut, 0, len(r.accounts))
	carryOut := Carry{AsOf: asOf, Accounts: []CarryAccount{}}
	for _, a := range r.accounts {
		root := r.rootOf(a)
		i, ok := g.Index[root]
		w := ws2[a]
		sc := ScoreOut{Account: a, Root: root}
		parts := Parts{World: []WorldItem{}, Backers: []FlowPart{}, Backs: []FlowPart{}, NodeCapCents: p.NodeCapCents, FadePPM: w.fade,
			GraceFromDay: w.last, ActiveDays: w.active, AccuracyPPM: accuracy(a), Judged: am.marked[a],
			Burn: BurnPreview{ProofRoots: []string{}, Backers: []BackerAtRisk{}}}
		parts.GraceDays = max(0, p.GraceDays-(D-1-w.last))
		for _, it := range items[a] {
			if it.Cents > 0 {
				it.Cents = mulDiv(it.Cents*mc, w.fade, 1e6) / mc
			}
			parts.World = append(parts.World, it)
		}
		if w.money > 0 {
			parts.World = append(parts.World, WorldItem{Kind: "money", Source: "paid_to_swarmmemo", Root: "money:" + a, State: "counted", PriceCents: w.money / mc, Cents: w.money / mc})
		}
		if w.time > 0 {
			parts.World = append(parts.World, WorldItem{Kind: "time_present", Source: "active_days", Root: "time:" + a, State: "counted", PriceCents: w.time / mc, Cents: w.time / mc,
				Note: strconv.FormatInt(p.DayPriceCents, 10) + "¢ per active day, at most " + strconv.FormatInt(p.TimeCapCents, 10) + "¢"})
		}
		if paidOut[a] > 0 {
			parts.World = append(parts.World, WorldItem{Kind: "money", Source: "usdc_paid", Root: "usdc:" + a, State: "counted", PriceCents: paidOut[a] / mc, Cents: paidOut[a] / mc,
				Note: strconv.FormatInt(paidOutN[a], 10) + " settled USDC payment(s) to independent accounts within funded_days, each up to the payee's direct costs or the wallet row's fallback"})
		}
		if paid[a] > 0 {
			parts.World = append(parts.World, WorldItem{Kind: "payments", Source: "independent_payments", Root: "payments:" + a, State: "counted", PriceCents: paid[a] / mc, Cents: paid[a] / mc,
				Note: strconv.FormatInt(paidN[a], 10) + " payment(s) within funded_days, each up to the payee's direct costs"})
		}
		parts.WorldCents, parts.DirectCents = worldMC[a]/mc, directMC[a]/mc
		if e := member[root]; e != nil {
			parts.Penalty = &PenaltyState{Entry: e.id, Role: "member", FractionPPM: 1e6, Level: e.level, EndsAt: e.end}
			for _, pen := range penalties {
				if pen.ID == e.id {
					parts.Penalty.Level, parts.Penalty.EndsAt = pen.Level, pen.EndsAt
				}
			}
			sum.Penalised++
		} else if l, ok := liable[root]; ok {
			cp := l
			parts.Penalty = &cp
			sum.Liable++
		}
		if ok {
			sc.Cents = res.Standing[i] / mc
			parts.RootWorldCents, parts.OwnCents, parts.PassedCents = g.World[i]/mc, res.Own[i]/mc, res.Passed[i]/mc
			parts.ReceivedCents = (res.Standing[i] - res.Own[i]) / mc
			parts.Backers, parts.BackersTotal = topFlows(inFlows[i], g)
			parts.Backs, parts.BacksTotal = topFlows(outFlows[i], g)
			parts.Burn = g.burnPreview(i, res, r, proofRootsOf, U)
		}
		sc.Band = p.Band(sc.Cents).Name()
		sc.VoteWeightPPM = p.VoteWeight(sc.Cents)
		sc.Parts = parts
		if w.active > 0 {
			sum.ActiveAccounts++
		}
		sum.Bands[sc.Band]++
		if sc.Cents >= p.VFloorCents {
			sum.AboveVoteFloor++
		}
		scores = append(scores, sc)
		ca := CarryAccount{Account: a, Money: w.money, Time: w.time, FadePPM: w.fade, LastActive: w.last, Direct: directMC[a] / mc, Standing: sc.Cents,
			Backed: backed[a] + newBacked[a]}
		if penalised(a) {
			ca.Money, ca.Time = 0, 0
		}
		carryOut.Accounts = append(carryOut.Accounts, ca)
	}
	summary := InputsSummary{EventsSeq: snap.Meta.EventsSeq, EndorsementsSeq: snap.Meta.EndorsementsSeq, LedgerSeq: snap.Meta.LedgerSeq,
		Accounts: int64(len(snap.Accounts)), Posts: int64(len(snap.Posts)), Endorsements: int64(len(snap.Endorsements)), Proofs: int64(len(snap.Proofs)),
		Transfers: int64(len(snap.Transfers)), Payments: int64(len(snap.Payments)), Acts: int64(len(snap.Acts)), Reviews: int64(len(snap.Reviews)),
		PenaltyEntries: int64(len(r.logIDs))}
	if penalties == nil {
		penalties = []PenaltyOut{}
	}
	return Output{Schema: SnapshotSchema, Rule: "RFC 0021", AsOf: asOf, ParamsVersion: p.Version, ParamsSHA256: sha256Hex(p.Body()), CarryIn: carryIn,
		Inputs: summary, Nodes: int64(len(g.Labels)), Edges: int64(len(g.Src)), Summary: sum, Scores: scores, Evidence: evidence, Penalties: penalties,
		Carry: carryOut, Graph: g, Work: r.work}, nil
}

// SettledPaymentKind reports whether a payment record of this kind is USDC
// settled on chain from the payer to the payee's payout address, its
// transaction verified (work_usdc: a work reward settled by work.settle;
// offering: a paid offering call), as against credit committed inside
// SwarmMemo (x402).
func SettledPaymentKind(kind string) bool { return kind == "work_usdc" || kind == "offering" }

func sumValues(m map[string]int64) int64 {
	var s int64
	for _, v := range m {
		s += v
	}
	return s
}

// labels names each root of u: its smallest domain root, else its smallest
// account (an address key never names a root).
func labels(u uf) map[string]string {
	label := map[string]string{}
	keys := make([]string, 0, len(u))
	for x := range u {
		keys = append(keys, x)
	}
	sort.Strings(keys)
	rank := func(x string) int {
		switch {
		case strings.HasPrefix(x, "domain:"):
			return 0
		case strings.Contains(x, ":"):
			return 2
		}
		return 1
	}
	for _, x := range keys {
		rep := u.find(x)
		cur, ok := label[rep]
		if !ok || rank(x) < rank(cur) || rank(x) == rank(cur) && x < cur {
			label[rep] = x
		}
	}
	return label
}

// Carry is what a run hands the next: each account's world accumulators.
type Carry struct {
	AsOf     int64          `json:"as_of"`
	Accounts []CarryAccount `json:"accounts"`
}

// CarryAccount is one account's carried world edge: money paid here and
// time present (millicents, faded), what inactivity left of its proofs
// (FadePPM), its last active day, its direct costs and standing (cents:
// next run's budgets and responder floor) and the time present it backs
// (millicents, decaying with H).
type CarryAccount struct {
	Account    string `json:"account"`
	Money      int64  `json:"money"`
	Time       int64  `json:"time"`
	FadePPM    int64  `json:"fade_ppm"`
	LastActive int64  `json:"last_active"`
	Direct     int64  `json:"direct"`
	Standing   int64  `json:"standing"`
	Backed     int64  `json:"backed"`
}

// Records is the carry as snapshot records, what the next run reads.
func (c Carry) Records() []Record {
	out := []Record{{Type: "carry", Kind: "run", AsOf: c.AsOf}}
	for _, a := range c.Accounts {
		if a.Money == 0 && a.Time == 0 && a.FadePPM == 1e6 && a.Direct == 0 && a.Standing == 0 && a.Backed == 0 {
			continue
		}
		out = append(out, Record{Type: "carry", Kind: "world", Account: a.Account, Amount: a.Money, Time: a.Time, FractionPPM: a.FadePPM,
			LastActive: a.LastActive, Direct: a.Direct, Standing: a.Standing, Backed: a.Backed})
	}
	return out
}
