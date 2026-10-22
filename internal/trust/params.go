package trust

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"swarmmemo/internal/judge"
)

// Params is the trust parameter namespace (RFC 0021 §11). Every number the
// run uses is here, so re-pricing is a new version, never a code change.
// Amounts are integers: ppm for fractions, US cents for prices.
//
// RFC 0021 has four knobs (grace_days, dormant_half_life_days,
// half_life_days and evidence_weight_ppm); unit_cents and min_judges are
// fixed, theta2, v_floor, c_ref and node_cap are derived from unit_cents
// (published so a reader sees them, and checked against the formula); the
// rest is data: price rows, the day price, the domain suffixes and the
// operator accounts (read only by the operator dashboard: no rule treats
// them differently).
//
// Decay and ramp curves never evaluate a float at run time: each curve
// publishes DayFactorPPM = round(1e6 × 2^(−1/half_life_days)) and the run
// applies it once per whole day with floor (see decayTable). Validation
// checks the factor against the half-life; the run reads only the factor.
type Params struct {
	Version        int64  `json:"-"`
	Schema         int64  `json:"schema"`
	CollateralUnit string `json:"collateral_unit"`

	// The knobs. G: a world edge holds this long after the last active
	// day; Hd: then it halves every Hd days; H: the half-life of judgement
	// edges, accuracy and funded_days; the evidence weights by class.
	GraceDays           int64            `json:"grace_days"`
	DormantHalfLifeDays int64            `json:"dormant_half_life_days"`
	DormantDayFactorPPM int64            `json:"dormant_day_factor_ppm"`
	HalfLifeDays        int64            `json:"half_life_days"`
	DayFactorPPM        int64            `json:"day_factor_ppm"`
	EvidenceWeightPPM   map[string]int64 `json:"evidence_weight_ppm"`

	// Fixed: U, a full judgement edge in cents and the liability's half
	// point; m, the score prior's weight and the independent later
	// judgements a judgement needs before its accuracy counts.
	UnitCents int64 `json:"unit_cents"`
	MinJudges int64 `json:"min_judges"`

	// Derived from U (checked): theta2 = U (proven), v_floor = U/4,
	// c_ref = 2.5 U, node_cap = 3.75 U (trusted). V0PPM is v(s)'s base.
	Theta2Cents  int64 `json:"theta2_cents"`
	VFloorCents  int64 `json:"v_floor_cents"`
	CRefCents    int64 `json:"c_ref_cents"`
	NodeCapCents int64 `json:"node_cap_cents"`
	V0PPM        int64 `json:"v0_ppm"`

	// Fixed (version 10, C336): a root offers its judgement edges what it
	// holds above node_cap topped up to this share of what it keeps, at
	// most its edges' total capacity (§2.1, Graph.setPass). Versions 8 and
	// 9 offer only the surplus (0, omitted from their bodies).
	PassSharePPM int64 `json:"pass_share_ppm,omitempty"`

	// Fixed (version 11, C338): how many days an account-change breaker
	// (RFC 0012 §2.4, account_breakers) keeps its account's judgements from
	// making edges and its replies from making active days, by the
	// breaker's reason: min(the row's trust_until, started_at + these
	// days). A reason it does not name keeps the row's trust_until, as
	// versions 8 to 10 do for every reason. RFC 0021 §2.2 says why each
	// window still bounds the damage.
	BreakerTrustDays map[string]int64 `json:"breaker_trust_days,omitempty"`

	// Data: the price rows (§10), the day price of time present and its
	// cap (§2), the coarse acts' x on an edge, the evidence class of each
	// act that is not a review, the public suffixes, the operator accounts.
	Proofs         map[string]ProofPrice `json:"proofs"`
	DomainSuffixes []string              `json:"domain_suffixes"`
	ProofFreshDays int64                 `json:"proof_fresh_days"`
	DayPriceCents  int64                 `json:"day_price_cents"`
	TimeCapCents   int64                 `json:"time_cap_cents"`
	CoarseX        int64                 `json:"coarse_x"`
	ActEvidence    map[string]string     `json:"act_evidence"`

	// Penalties (§8): fixed by the RFC.
	Detectors Detectors `json:"detectors"`
	Penalty   Penalty   `json:"penalty"`

	// Run bounds.
	WindowDays int64 `json:"window_days"`
	NMax       int64 `json:"n_max"`
	MaxWork    int64 `json:"max_work"`
	MaxSeconds int64 `json:"max_seconds"`
}

// ProofPrice prices one proof kind at min(forge, rent), times its curve.
//
// An assessed row (wallet, github, pow; roots.go) prices a proof by the
// assessment its record carries: Assess names the rule (capped or
// saturating), UnitsPerCent converts the assessment to cents, and
// min(forge, rent) is the cap. The domain row (Assess "domain", §10) is
// AgeCents × ramp(registration age) + RankCents × max(0, 1 − log₁₀(rank)/6),
// at most min(forge, rent); an unknown age or rank counts 0, and a domain
// with neither yet prices at FallbackCents (the old flat domain value).
type ProofPrice struct {
	Forge        int64  `json:"forge"`
	Rent         int64  `json:"rent"`
	Curve        string `json:"curve"` // "ramp" or "none"
	HalfLifeDays int64  `json:"half_life_days"`
	DayFactorPPM int64  `json:"day_factor_ppm"`
	Assess       string `json:"assess,omitempty"`
	UnitsPerCent int64  `json:"units_per_cent,omitempty"`
	AgeCents     int64  `json:"age_cents,omitempty"`
	RankCents    int64  `json:"rank_cents,omitempty"`
	// FallbackCents prices a verified domain whose registration age and
	// rank are not fetched yet (the domain row), and is the least a
	// verified wallet prices at (the wallet row, AssessedContribution).
	FallbackCents int64 `json:"fallback_cents,omitempty"`
}

// Detectors are the versioned evidence detectors (§8, RFC 0012 §4.5).
type Detectors struct {
	Version        int64 `json:"version"`
	FunnelK        int64 `json:"funnel_k"`
	FunnelDays     int64 `json:"funnel_days"`
	FunnelSpendPPM int64 `json:"funnel_spend_ppm"`
	RingMin        int64 `json:"ring_min"`
	RingInsidePPM  int64 `json:"ring_inside_ppm"`
}

// Penalty is RFC 0021 §8's burn: the k-th penalty on a root within
// EscalationDays lasts BaseDays × DurationFactor^(k−1) days; a backer (an
// edge into the penalised set within BackerEdgeDays) loses
// f = c / (c + U) of its standing, its k-th liability within EscalationDays
// min(1, BackerFactor^(k−1) × f).
type Penalty struct {
	BaseDays       int64 `json:"base_days"`
	DurationFactor int64 `json:"duration_factor"`
	BackerFactor   int64 `json:"backer_factor"`
	EscalationDays int64 `json:"escalation_days"`
	BackerEdgeDays int64 `json:"backer_edge_days"`
	MaxLevel       int64 `json:"max_level"`
}

// ParamsNamespace is the parameter namespace of the trust module.
const ParamsNamespace = "trust"

// UnifiedVersion is RFC 0021's parameter version (rule 5, the one trust
// graph): the first the run computes. Versions 1 to 7 (RFC 0012's seeds
// and tiers, RFC 0015's rules 0-3, RFC 0020's marks) are retired: their
// runs stay published with their output_sha256, and scripts/trust/
// recompute.py still verifies versions 1 to 6 (docs/rfcs/0021 §14).
const UnifiedVersion = 8

// ProofsVersion is version 8 plus the price rows of C326's proof
// providers (roots.go, proofRowsV9): OAuth identities, Farcaster, ENS,
// package maintainers and the refundable bond. Rows only: the run is rule 5
// unchanged, and a snapshot without these kinds computes the same standing.
const ProofsVersion = 9

// PassVersion is version 9 plus C336's pass share (pass_share_ppm, RFC 0021
// §2.1): a root offers its judgement edges what it holds above node_cap
// topped up to a quarter of what it keeps, so judgement passes standing
// before anyone holds more than node_cap. Standing stays conserved.
const PassVersion = 10

// DefaultPassSharePPM is version 10's pass_share_ppm: a quarter.
const DefaultPassSharePPM = 250000

// BreakerVersion is version 10 plus C338's breaker windows
// (breaker_trust_days, RFC 0021 §2.2): a key rotation or a dormant key's
// return still silences an account's judgements for 30 days, a proof link
// or unlink for 7, and a spike in outbound credit transfers (paying
// bounties) no longer does: the conserved flow bounds what any judgement
// passes, and the ledger still delays the transfers.
const BreakerVersion = 11

// breakerReasons are the reasons an account_breakers row names
// (ledger.Breaker).
var breakerReasons = []string{"agent.rotate", "dormant", "identity.link", "identity.unlink", "spike"}

// DefaultBreakerTrustDays is version 11's breaker_trust_days.
func DefaultBreakerTrustDays() map[string]int64 {
	return map[string]int64{"agent.rotate": 30, "dormant": 30, "identity.link": 7, "identity.unlink": 7, "spike": 0}
}

// FloorOnceVersion is version 11 plus C492's rule: a capped row's
// fallback_cents (the wallet's 50¢) counts once per (kind, node root), on
// the root's best claim; its other claims of that kind price at their
// assessed value alone (AssessedValue), so N fresh empty wallets add 50¢,
// not N × 50¢. The rule only: the body is version 11's, and runs at
// versions up to 11 compute as before, so their published outputs still
// recompute.
const FloorOnceVersion = 12

// DomainFloorOnceVersion is version 12 plus C515's rule: a domain priced at
// the domain row's fallback_cents (the 400¢ for neither registration age
// nor rank known) counts that floor once per node root, on the root's best
// such claim; its other fallback-priced domains price at 0, their value
// with no signal, so N domains whose signals cannot be fetched add 400¢,
// not N × 400¢. Domains priced by age or rank still stack. The rule only:
// the body is version 12's, and runs at versions up to 12 compute as
// before.
const DomainFloorOnceVersion = 13

// DefaultVersion is the compiled-in trust parameter version: RFC 0021 with
// C326's price rows, C336's pass share, C338's breaker windows, C492's
// once-per-root fallback and C515's once-per-root domain fallback, active
// from the deploy that ships it (no parameter write is needed).
const DefaultVersion = DomainFloorOnceVersion

// Evidence classes (RFC 0015 §5.4, judge.EvidenceWeightPPM).
var evidenceClasses = []string{"free_use", "observed", "opinion", "paid_use", "work"}

// judgementActs are the acts that are not reviews, each read as one
// evidence class (Params.ActEvidence).
var judgementActs = []string{judge.ActVote, judge.ActVouch, judge.ActWitness, judge.ActWorkAccept}

// DayFactor is round(1e6 × 2^(−1/h)), the published daily factor of a curve
// with half-life h days. It is evaluated when parameters are made or checked,
// never during a run.
func DayFactor(halfLifeDays int64) int64 {
	if halfLifeDays <= 0 {
		return 0
	}
	return int64(math.Round(1e6 * math.Pow(2, -1/float64(halfLifeDays))))
}

// DefaultParams is the compiled-in parameter set (version 13): RFC 0021's
// knobs (G 120 days, Hd 180, H 180, the evidence weights), U = 200¢ and
// m = 2, the values derived from them, the price rows of §10 and C326's
// (proofRowsV9), C336's pass share and C338's breaker windows, under C492's
// and C515's once-per-root fallbacks. FloorOnceParams is version 12, the
// same body without C515's rule; BreakerParams is version 11, also without
// C492's; PassParams
// is version 10, also without the breaker windows; ProofsParams version
// 9, also without the pass share; UnifiedParams version 8, also without
// C326's rows.
func DefaultParams() Params {
	p := Params{
		Version:             DefaultVersion,
		Schema:              2,
		CollateralUnit:      "usd_cent",
		GraceDays:           120,
		DormantHalfLifeDays: 180,
		DormantDayFactorPPM: DayFactor(180),
		HalfLifeDays:        judge.HalfLifeDays,
		DayFactorPPM:        judge.DayFactorPPM,
		EvidenceWeightPPM:   maps2(judge.EvidenceWeightPPM),
		UnitCents:           200,
		MinJudges:           judge.PriorWeight,
		V0PPM:               250000,
		PassSharePPM:        DefaultPassSharePPM,
		BreakerTrustDays:    DefaultBreakerTrustDays(),
		Proofs: map[string]ProofPrice{
			// §10: age (RDAP) + rank (Tranco), ≤ 600¢; unknown counts 0;
			// with neither fetched yet, the old flat 400¢.
			"domain":  {Forge: 1200, Rent: 600, Curve: "ramp", HalfLifeDays: 365, DayFactorPPM: DayFactor(365), Assess: AssessDomain, AgeCents: 200, RankCents: 400, FallbackCents: 400},
			"ed25519": {Curve: "none"},
			"board":   {Curve: "none"},
			"url":     {Curve: "none"},
			"nostr":   {Curve: "none"},
		},
		DomainSuffixes: []string{"ac.uk", "co.jp", "co.nz", "co.uk", "co.za", "com.au", "com.br", "com.cn", "github.io", "gov.uk", "net.au", "org.au", "org.uk", "pages.dev", "vercel.app"},
		ProofFreshDays: 30,
		DayPriceCents:  10,
		TimeCapCents:   900,
		CoarseX:        75,
		ActEvidence:    map[string]string{judge.ActVote: "opinion", judge.ActVouch: "opinion", judge.ActWitness: "observed", judge.ActWorkAccept: "work"},
		Detectors:      Detectors{Version: 2, FunnelK: 5, FunnelDays: 7, FunnelSpendPPM: 100000, RingMin: 3, RingInsidePPM: 800000},
		Penalty:        Penalty{BaseDays: 30, DurationFactor: 4, BackerFactor: 2, EscalationDays: 365, BackerEdgeDays: 30, MaxLevel: 8},
		WindowDays:     judge.HalfLifeDays,
		NMax:           20000,
		MaxWork:        400000000,
		MaxSeconds:     300,
	}
	p.Derive()
	for kind, row := range assessedRows() {
		p.Proofs[kind] = row
	}
	for kind, row := range proofRowsV9() {
		p.Proofs[kind] = row
	}
	return p
}

// FloorOnceParams is parameter version 12: DefaultParams' body, without
// C515's once-per-root domain fallback (each fallback-priced domain's floor
// counts).
func FloorOnceParams() Params {
	p := DefaultParams()
	p.Version = FloorOnceVersion
	return p
}

// BreakerParams is parameter version 11: FloorOnceParams' body, without
// C492's once-per-root fallback (each wallet's floor counts).
func BreakerParams() Params {
	p := FloorOnceParams()
	p.Version = BreakerVersion
	return p
}

// PassParams is parameter version 10: BreakerParams without the breaker
// windows.
func PassParams() Params {
	p := BreakerParams()
	p.Version, p.BreakerTrustDays = PassVersion, nil
	return p
}

// ProofsParams is parameter version 9: PassParams without the pass share.
func ProofsParams() Params {
	p := PassParams()
	p.Version, p.PassSharePPM = ProofsVersion, 0
	return p
}

// UnifiedParams is parameter version 8: ProofsParams without C326's rows.
func UnifiedParams() Params {
	p := ProofsParams()
	p.Version = UnifiedVersion
	for kind := range proofRowsV9() {
		delete(p.Proofs, kind)
	}
	for kind, row := range assessedRows() {
		p.Proofs[kind] = row
	}
	return p
}

// OfferCents is what a root holding world cents (its own costs) offers its
// judgement edges (§2): what it holds above node_cap, topped up to pass_share_ppm
// of what it keeps, before its edges' capacity bounds it. Copy that states
// what a backer passes on reads it and PassPercent, never a literal.
func (p Params) OfferCents(world int64) int64 {
	keep := min(max(0, world), p.NodeCapCents)
	return max(world-keep, mulDiv(keep, p.PassSharePPM, 1e6))
}

// BreakerUntil is when a breaker row stops silencing its account's
// judgements under p: its trust_until, or started_at plus the days
// breaker_trust_days names for its reason (the record's kind) if sooner.
func (p Params) BreakerUntil(r Record) int64 {
	if d, ok := p.BreakerTrustDays[r.Kind]; ok {
		return min(r.TrustUntil, r.StartedAt+d*day)
	}
	return r.TrustUntil
}

// PassPercent is pass_share_ppm as copy reads it ("25%").
func (p Params) PassPercent() string {
	return strconv.FormatFloat(float64(p.PassSharePPM)/1e4, 'f', -1, 64) + "%"
}

// Derive sets the values RFC 0021 derives from U.
func (p *Params) Derive() {
	U := p.UnitCents
	p.Theta2Cents, p.VFloorCents, p.CRefCents, p.NodeCapCents = U, U/4, U*5/2, U*15/4
}

func maps2(m map[string]int64) map[string]int64 {
	out := make(map[string]int64, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// Body is the canonical JSON of the parameter set (sorted keys, no spaces),
// the form published at /api/params/trust and hashed into every run.
func (p Params) Body() []byte {
	raw, err := json.Marshal(p)
	if err != nil {
		panic(err) // Params holds only strings, integers, slices and maps
	}
	return canonicalize(raw)
}

var accountRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ErrRetiredVersion is the refusal of a retired parameter version.
type ErrRetiredVersion struct{ Version int64 }

func (e ErrRetiredVersion) Error() string {
	return fmt.Sprintf("trust params: version %d is retired (RFC 0021 replaced it with version %d, the one trust graph); its runs stay published with their output_sha256, and scripts/trust/recompute.py verifies versions 1 to 6", e.Version, UnifiedVersion)
}

// ParseParams reads a trust parameter body strictly: unknown fields, missing
// sections and values outside their bounds are errors, and so is a retired
// version (before UnifiedVersion).
func ParseParams(version int64, body []byte) (Params, error) {
	if version < UnifiedVersion {
		return Params{}, ErrRetiredVersion{version}
	}
	var p Params
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	dec.UseNumber()
	if err := dec.Decode(&p); err != nil {
		return Params{}, fmt.Errorf("trust params: %w", err)
	}
	if dec.More() {
		return Params{}, fmt.Errorf("trust params: trailing data")
	}
	p.Version = version
	if err := p.Validate(); err != nil {
		return Params{}, err
	}
	return p, nil
}

// Validate checks every bound. A parameter set that passes cannot make a run
// overflow int64 or loop without bound.
func (p Params) Validate() error {
	var errs []string
	check := func(ok bool, format string, args ...any) {
		if !ok {
			errs = append(errs, fmt.Sprintf(format, args...))
		}
	}
	in := func(name string, v, lo, hi int64) {
		check(v >= lo && v <= hi, "%s must be %d–%d, not %d", name, lo, hi, v)
	}
	curve := func(name string, h, factor int64) {
		in(name+"half_life_days", h, 1, 3650)
		check(factor >= DayFactor(h)-1 && factor <= DayFactor(h)+1, "%sday_factor_ppm must be round(1e6×2^(−1/%d)) = %d, not %d", name, h, DayFactor(h), factor)
	}
	check(p.Schema == 2, "schema must be 2")
	check(p.CollateralUnit == "usd_cent", "collateral_unit must be usd_cent")
	in("grace_days", p.GraceDays, 0, 3650)
	in("dormant_half_life_days", p.DormantHalfLifeDays, 1, 3650)
	check(p.DormantDayFactorPPM >= DayFactor(p.DormantHalfLifeDays)-1 && p.DormantDayFactorPPM <= DayFactor(p.DormantHalfLifeDays)+1,
		"dormant_day_factor_ppm must be round(1e6×2^(−1/%d)) = %d", p.DormantHalfLifeDays, DayFactor(p.DormantHalfLifeDays))
	curve("", p.HalfLifeDays, p.DayFactorPPM)
	check(len(p.EvidenceWeightPPM) == len(evidenceClasses), "evidence_weight_ppm names exactly %s", strings.Join(evidenceClasses, ", "))
	for _, c := range evidenceClasses {
		w, ok := p.EvidenceWeightPPM[c]
		check(ok, "evidence_weight_ppm.%s is required", c)
		in("evidence_weight_ppm."+c, w, 0, 1e6)
	}
	in("unit_cents", p.UnitCents, 4, 1e7)
	in("min_judges", p.MinJudges, 1, 100)
	d := p
	d.Derive()
	check(p.Theta2Cents == d.Theta2Cents && p.VFloorCents == d.VFloorCents && p.CRefCents == d.CRefCents && p.NodeCapCents == d.NodeCapCents,
		"theta2_cents, v_floor_cents, c_ref_cents and node_cap_cents are U, U/4, 2.5U and 3.75U (%d, %d, %d, %d)", d.Theta2Cents, d.VFloorCents, d.CRefCents, d.NodeCapCents)
	in("v0_ppm", p.V0PPM, 0, 1e6)
	in("pass_share_ppm", p.PassSharePPM, 0, 1e6)
	check(p.Version >= PassVersion || p.PassSharePPM == 0, "pass_share_ppm is version %d's: earlier versions offer none", PassVersion)
	check(p.Version >= BreakerVersion || p.BreakerTrustDays == nil, "breaker_trust_days is version %d's: earlier versions keep each breaker's trust_until", BreakerVersion)
	for reason, d := range p.BreakerTrustDays {
		check(slices.Contains(breakerReasons, reason), "breaker_trust_days.%s is not a breaker reason (%s)", reason, strings.Join(breakerReasons, ", "))
		in("breaker_trust_days."+reason, d, 0, 365)
	}
	for _, kind := range []string{"domain", "ed25519", "board", "url", "nostr"} {
		_, ok := p.Proofs[kind]
		check(ok, "proofs.%s is required", kind)
	}
	for kind, pr := range p.Proofs {
		name := "proofs." + kind + "."
		in(name+"forge", pr.Forge, 0, 1e7)
		in(name+"rent", pr.Rent, 0, 1e7)
		want, assessed := assessedKinds[kind]
		switch {
		case kind == "domain":
			check(pr.Assess == AssessDomain && pr.Curve == "ramp", "proofs.domain is priced by age and rank (assess domain, curve ramp)")
			curve(name, pr.HalfLifeDays, pr.DayFactorPPM)
			in(name+"age_cents", pr.AgeCents, 0, 1e7)
			in(name+"rank_cents", pr.RankCents, 0, 1e7)
			in(name+"fallback_cents", pr.FallbackCents, 0, 1e7)
		case assessed:
			in(name+"units_per_cent", pr.UnitsPerCent, 1, 1e9)
			check(pr.Assess == want, "%sassess must be %s", name, want)
			check(pr.Curve == "none" && pr.HalfLifeDays == 0 && pr.DayFactorPPM == 0, "proofs.%s: an assessed row takes curve none", kind)
		case kind == "ed25519" || kind == "board" || kind == "url" || kind == "nostr":
			check(pr.Curve == "none" && pr.Assess == "" && pr.Forge == 0 && pr.Rent == 0, "proofs.%s prices nothing: it proves control, not cost", kind)
		default:
			check(false, "proofs.%s is not a known proof kind", kind)
		}
		switch {
		case kind == "wallet":
			check(pr.AgeCents == 0 && pr.RankCents == 0, "%sage_cents and rank_cents are the domain row's", name)
			in(name+"fallback_cents", pr.FallbackCents, 0, 1e7)
		case kind != "domain":
			check(pr.AgeCents == 0 && pr.RankCents == 0 && pr.FallbackCents == 0, "%sage_cents, rank_cents and fallback_cents are the domain and wallet rows'", name)
		}
	}
	check(len(p.DomainSuffixes) <= 1024, "domain_suffixes lists at most 1024 suffixes")
	for _, s := range p.DomainSuffixes {
		check(strings.Count(s, ".") >= 1 && s == strings.ToLower(s) && !strings.HasPrefix(s, ".") && !strings.HasSuffix(s, "."), "domain suffix %q must be lowercase with two or more labels", s)
	}
	in("proof_fresh_days", p.ProofFreshDays, 1, 365)
	in("day_price_cents", p.DayPriceCents, 0, 1e5)
	in("time_cap_cents", p.TimeCapCents, 0, 1e7)
	in("coarse_x", p.CoarseX, judge.Neutral+1, judge.Max)
	check(len(p.ActEvidence) == len(judgementActs), "act_evidence names exactly %v", judgementActs)
	for _, act := range judgementActs {
		c, ok := p.ActEvidence[act]
		_, known := p.EvidenceWeightPPM[c]
		check(ok && known, "act_evidence.%s must name an evidence class", act)
	}
	in("detectors.version", p.Detectors.Version, 1, 1e6)
	in("detectors.funnel_k", p.Detectors.FunnelK, 2, 1000)
	in("detectors.funnel_days", p.Detectors.FunnelDays, 1, 90)
	in("detectors.funnel_spend_ppm", p.Detectors.FunnelSpendPPM, 0, 1e6)
	in("detectors.ring_min", p.Detectors.RingMin, 2, 1000)
	in("detectors.ring_inside_ppm", p.Detectors.RingInsidePPM, 0, 1e6)
	in("penalty.base_days", p.Penalty.BaseDays, 1, 365)
	in("penalty.duration_factor", p.Penalty.DurationFactor, 1, 16)
	in("penalty.backer_factor", p.Penalty.BackerFactor, 1, 16)
	in("penalty.escalation_days", p.Penalty.EscalationDays, 1, 3650)
	in("penalty.backer_edge_days", p.Penalty.BackerEdgeDays, 1, 365)
	in("penalty.max_level", p.Penalty.MaxLevel, 1, 10)
	in("window_days", p.WindowDays, 1, 400)
	in("n_max", p.NMax, 1, 100000)
	in("max_work", p.MaxWork, 1, 1e11)
	in("max_seconds", p.MaxSeconds, 1, 3600)
	if len(errs) > 0 {
		return fmt.Errorf("trust params: %s", strings.Join(errs, "; "))
	}
	return nil
}

// decayTable is 1e6 × f^days with f = factor/1e6, applied one whole day at a
// time with floor: v₀ = 1e6, vₙ₊₁ = ⌊vₙ × factor / 1e6⌋. Ages past 3650
// days use 3650. It is the only curve evaluation in a run.
type decayTable struct {
	factor int64
	values []int64
}

func (t *decayTable) at(days int64) int64 {
	if days <= 0 {
		return 1e6
	}
	if days > 3650 {
		days = 3650
	}
	if t.values == nil {
		t.values = []int64{1e6}
	}
	for int64(len(t.values)) <= days {
		last := t.values[len(t.values)-1]
		t.values = append(t.values, last*t.factor/1e6)
	}
	return t.values[days]
}

// curves memoizes decay tables by factor.
type curves map[int64]*decayTable

func (c curves) decay(factor, days int64) int64 {
	t := c[factor]
	if t == nil {
		t = &decayTable{factor: factor}
		c[factor] = t
	}
	return t.at(days)
}

// ramp is 1e6 − decay: the weight a proof earns by surviving.
func (c curves) ramp(factor, days int64) int64 { return 1e6 - c.decay(factor, days) }

// NewDecay returns the run's decay curve, memoized: decay(factor, days) is
// what a run applies at that age.
func NewDecay() func(factor, days int64) int64 { return curves{}.decay }

// Fixed-point helpers. mulDiv is ⌊a × b / c⌋ for non-negative a, b and
// positive c, exact in 128 bits (judge.MulDiv, the one copy).
func mulDiv(a, b, c int64) int64 { return judge.MulDiv(a, b, c) }
