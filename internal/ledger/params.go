package ledger

// Versioned parameters (RFC0012 §2.7, RFC 0021 §12). Every number of the
// share rule is a parameter, never a constant: the compiled-in set is version
// 0 of the "allowance" namespace; "swarmmemo params set" appends versions,
// never edits one. Bodies are strict JSON: unknown, missing or duplicate
// keys, trailing data and values out of bounds are refused.
//
// The current body is schema 2 (the share rule). Schema 1 bodies (RFC 0012's
// per-tier arrays), already stored in the params table, still parse: they
// are converted to schema 2 on reading (allowanceParamsV1.convert). "params set" takes
// schema 2 only.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"sync"

	"swarmmemo/internal/allowance"
)

// AllowanceNamespace is the namespace of the ledger's parameters.
const AllowanceNamespace = "allowance"

// AllowanceSchema is the schema of the bodies the ledger writes.
const AllowanceSchema = 2

// Bounds shared by the parser and the ledger.
const (
	maxUnits       = int64(1) << 42 // any budget, cap or amount
	ppm            = int64(1_000_000)
	maxHalfLife    = int64(3650)
	maxParamsBytes = 64 << 10
)

// ResourceParams are one resource's share-rule parameters (RFC 0021 §12).
// Of the day's budget (less a pulled cut-budget lever), the grant slice
// (grant_share_ppm) funds operator grants; of the rest, the floor slice
// (floor_slice_ppm) gives every claimant min(floor, slice / expected
// claimants), and the standing slice (the remainder) is shared in proportion
// to standing, each root once; no claimant's entitlement exceeds cap.
// anonymous_share_ppm caps what anonymous lots draw of the day's budget (0:
// anonymous callers get nothing of the resource). spill_start and
// spill_interval pace how much of one slice's unspent water the other slice's
// spends may draw (unused water spills once).
type ResourceParams struct {
	Unit              string `json:"unit"`
	Budget            int64  `json:"budget"`
	SpendCeiling      int64  `json:"spend_ceiling"`
	GrantSharePPM     int64  `json:"grant_share_ppm"`
	FloorSlicePPM     int64  `json:"floor_slice_ppm"`
	Floor             int64  `json:"floor"`
	Cap               int64  `json:"cap"`
	AnonymousSharePPM int64  `json:"anonymous_share_ppm"`
	SpillStart        int64  `json:"spill_start"`
	SpillInterval     int64  `json:"spill_interval"`
	TransferFee       int64  `json:"transfer_fee"`
	InboundCap        int64  `json:"inbound_cap"`
	NewKeyFloor       int64  `json:"new_key_floor"`
	ClientSharePPM    int64  `json:"client_share_ppm"`
}

// AllowanceParams is the body of the "allowance" namespace. ClaimExpiryDays
// is how many days past the end of its UTC day a free lot lives, the same for
// every claimant; TransferableFree lets free units move by transfer.
type AllowanceParams struct {
	Schema              int                                    `json:"schema"`
	Resources           map[allowance.Resource]*ResourceParams `json:"resources"`
	ClaimExpiryDays     int64                                  `json:"claim_expiry_days"`
	ClaimHalfLifeDays   int64                                  `json:"claim_half_life_days"`
	ClaimRatePPM        int64                                  `json:"claim_rate_ppm"`
	GrantedHalfLifeDays int64                                  `json:"granted_half_life_days"`
	GrantedRatePPM      int64                                  `json:"granted_rate_ppm"`
	EarnedHalfLifeDays  int64                                  `json:"earned_half_life_days"`
	EarnedRatePPM       int64                                  `json:"earned_rate_ppm"`
	Dust                int64                                  `json:"dust"`
	TransferableFree    bool                                   `json:"transferable_free"`
	PaidTransferable    bool                                   `json:"paid_transferable"`
	TransferDelay       int64                                  `json:"transfer_delay"`
	DormantDays         int64                                  `json:"dormant_days"`
	SpikeX              int64                                  `json:"spike_x"`
	SpikeFloor          int64                                  `json:"spike_floor"`
	TrustResetDays      int64                                  `json:"trust_reset_days"`
}

// KnownResources is the resource registry (§2.1): a new resource is a
// parameter entry plus a line here.
var KnownResources = map[allowance.Resource]string{
	allowance.PostBytes:   "byte",
	allowance.MemoryBytes: "byte",
	allowance.Credit:      "credit",
}

// RatePPM is the daily demurrage rate of a half-life of h days:
// round((1 − 2^(−1/h)) × 1e6), 0 when h is 0 (no decay).
func RatePPM(h int64) int64 {
	if h <= 0 {
		return 0
	}
	return int64(math.Round((1 - math.Exp2(-1/float64(h))) * 1e6))
}

// defaultFloorSlicePPM is the floor slice's share: a quarter (RFC 0021 §12).
const defaultFloorSlicePPM = 250_000

// DefaultAllowanceParams is version 0: RFC 0021 §12's share rule, generous
// until SwarmMemo is resource-constrained (the owner, 2026-10-14, C320c: in
// two weeks of allowance_usage the busiest anonymous caller used under 1% of
// its post bytes and 20% of its credits). Each daily budget is twice the one
// in force before the share rule (post 64 → 128 MiB, memory 16 → 32 MiB,
// credit 1.6M → 3.2M), and the floor everyone gets, anonymous callers
// included, is today's anonymous share: 4 MiB of posts, 256 KiB of memory,
// 8,000 credits. Signed accounts also keep at least their waterfall share
// for TransitionFloorDays (pools.go). Credit's inbound_cap is its budget,
// as every resource's is (RFC 0012 §2.4): at 0 no credit could arrive by
// transfer, so on a board without published parameters every rewarded
// accept failed with recipient_limit (cold-start evaluation 2026-10-21).
// A published version names its own and is unaffected. grant_share_ppm
// stays 0: an operator who grants credit, or pays review and invite
// rewards, publishes a grant share (deploy/RUNBOOK.md).
func DefaultAllowanceParams() AllowanceParams {
	const mib = 1 << 20
	post := &ResourceParams{
		Unit: "byte", Budget: 128 * mib, SpendCeiling: 256 * mib, GrantSharePPM: 0,
		FloorSlicePPM: defaultFloorSlicePPM, Floor: 4 * mib, Cap: 16 * mib, AnonymousSharePPM: ppm,
		SpillStart: 3600, SpillInterval: 3600,
		TransferFee: 256, InboundCap: 128 * mib, NewKeyFloor: 0, ClientSharePPM: ppm,
	}
	memory := &ResourceParams{
		Unit: "byte", Budget: 32 * mib, SpendCeiling: 64 * mib, GrantSharePPM: 0,
		FloorSlicePPM: defaultFloorSlicePPM, Floor: 256 << 10, Cap: 4 * mib, AnonymousSharePPM: 250_000,
		SpillStart: 3600, SpillInterval: 3600,
		TransferFee: 256, InboundCap: 32 * mib, NewKeyFloor: 0, ClientSharePPM: ppm,
	}
	credit := &ResourceParams{
		Unit: "credit", Budget: 3_200_000, SpendCeiling: 3_200_000, GrantSharePPM: 0,
		FloorSlicePPM: defaultFloorSlicePPM, Floor: 8_000, Cap: 400_000, AnonymousSharePPM: 100_000,
		SpillStart: 3600, SpillInterval: 3600,
		TransferFee: 1, InboundCap: 3_200_000, NewKeyFloor: 0, ClientSharePPM: ppm,
	}
	return AllowanceParams{
		Schema:          AllowanceSchema,
		Resources:       map[allowance.Resource]*ResourceParams{allowance.PostBytes: post, allowance.MemoryBytes: memory, allowance.Credit: credit},
		ClaimExpiryDays: 0, ClaimHalfLifeDays: 0, ClaimRatePPM: 0,
		GrantedHalfLifeDays: 14, GrantedRatePPM: RatePPM(14),
		EarnedHalfLifeDays: 30, EarnedRatePPM: RatePPM(30),
		Dust: 64, TransferableFree: true, PaidTransferable: true,
		TransferDelay: 48 * 3600, DormantDays: 30, SpikeX: 4, SpikeFloor: 8, TrustResetDays: 30,
	}
}

// Clone is a deep copy.
func (p AllowanceParams) Clone() AllowanceParams {
	out := p
	out.Resources = make(map[allowance.Resource]*ResourceParams, len(p.Resources))
	for r, rp := range p.Resources {
		c := *rp
		out.Resources[r] = &c
	}
	return out
}

// Marshal is the canonical body: compact JSON with sorted map keys.
func (p AllowanceParams) Marshal() []byte {
	b, err := json.Marshal(p)
	if err != nil {
		panic(err) // plain structs of ints, bools and strings always encode
	}
	return b
}

// Validate checks every bound. A body that parses and validates is safe to
// run the share rule on: no division by zero, no overflow past maxUnits.
func (p AllowanceParams) Validate() error {
	if p.Schema != AllowanceSchema {
		return fmt.Errorf("schema must be %d", AllowanceSchema)
	}
	if len(p.Resources) != len(KnownResources) {
		return fmt.Errorf("resources must name exactly %d resources", len(KnownResources))
	}
	for r, unit := range KnownResources {
		rp := p.Resources[r]
		if rp == nil {
			return fmt.Errorf("resources.%s is missing", r)
		}
		if err := rp.validate(unit); err != nil {
			return fmt.Errorf("resources.%s: %w", r, err)
		}
	}
	checks := []struct {
		name      string
		v, lo, hi int64
	}{
		{"claim_expiry_days", p.ClaimExpiryDays, 0, 30},
		{"claim_half_life_days", p.ClaimHalfLifeDays, 0, maxHalfLife},
		{"granted_half_life_days", p.GrantedHalfLifeDays, 1, maxHalfLife},
		{"earned_half_life_days", p.EarnedHalfLifeDays, 1, maxHalfLife},
		{"dust", p.Dust, 0, 1 << 20},
		{"transfer_delay", p.TransferDelay, 0, 30 * 86400},
		{"dormant_days", p.DormantDays, 1, maxHalfLife},
		{"spike_x", p.SpikeX, 1, 1000},
		{"spike_floor", p.SpikeFloor, 1, 1_000_000},
		{"trust_reset_days", p.TrustResetDays, 0, maxHalfLife},
	}
	for _, c := range checks {
		if c.v < c.lo || c.v > c.hi {
			return fmt.Errorf("%s must be %d–%d", c.name, c.lo, c.hi)
		}
	}
	for _, rate := range []struct {
		name string
		h, r int64
	}{{"claim_rate_ppm", p.ClaimHalfLifeDays, p.ClaimRatePPM}, {"granted_rate_ppm", p.GrantedHalfLifeDays, p.GrantedRatePPM}, {"earned_rate_ppm", p.EarnedHalfLifeDays, p.EarnedRatePPM}} {
		if rate.r != RatePPM(rate.h) {
			return fmt.Errorf("%s must be %d, round((1 - 2^(-1/h)) * 1e6) of its half-life", rate.name, RatePPM(rate.h))
		}
	}
	return nil
}

func (rp *ResourceParams) validate(unit string) error {
	if rp.Unit != unit {
		return fmt.Errorf("unit must be %q", unit)
	}
	if rp.Budget < 0 || rp.Budget > maxUnits {
		return fmt.Errorf("budget must be 0–%d", maxUnits)
	}
	if rp.SpendCeiling < rp.Budget || rp.SpendCeiling > 8*rp.Budget {
		return errors.New("spend_ceiling must be from budget to 8 × budget")
	}
	for _, f := range []struct {
		name string
		v    int64
	}{{"grant_share_ppm", rp.GrantSharePPM}, {"floor_slice_ppm", rp.FloorSlicePPM}, {"anonymous_share_ppm", rp.AnonymousSharePPM}} {
		if !inPPM(f.v) {
			return fmt.Errorf("%s must be 0–1000000", f.name)
		}
	}
	if rp.Cap < 0 || rp.Cap > maxUnits {
		return fmt.Errorf("cap must be 0–%d", maxUnits)
	}
	if rp.Floor < 0 || rp.Floor > rp.Cap {
		return errors.New("floor must be 0–cap")
	}
	if rp.SpillStart < 0 || rp.SpillStart > 86399 {
		return errors.New("spill_start must be 0–86399 seconds")
	}
	if rp.SpillInterval < 60 || rp.SpillInterval > 86400 {
		return errors.New("spill_interval must be 60–86400 seconds")
	}
	if rp.TransferFee < 0 || rp.TransferFee > maxUnits {
		return errors.New("transfer_fee must be 0 or more")
	}
	if rp.InboundCap < 0 || rp.InboundCap > maxUnits {
		return errors.New("inbound_cap must be 0 or more")
	}
	if rp.NewKeyFloor < 0 || rp.NewKeyFloor > maxUnits {
		return errors.New("new_key_floor must be 0 or more")
	}
	if rp.ClientSharePPM < 1 || rp.ClientSharePPM > ppm {
		return errors.New("client_share_ppm must be 1–1000000")
	}
	return nil
}

func inPPM(v int64) bool { return v >= 0 && v <= ppm }

// ParseAllowanceParams parses and validates a strict body of schema 2, or of
// schema 1, converted to schema 2 (allowanceParamsV1.convert). It is what the ledger
// reads with; ParseAllowanceParamsSet is what a new version must pass.
func ParseAllowanceParams(body []byte) (AllowanceParams, error) {
	var head struct {
		Schema int `json:"schema"`
	}
	if err := json.Unmarshal(body, &head); err == nil && head.Schema == 1 {
		var v1 allowanceParamsV1
		if err = strictUnmarshal(body, &v1); err != nil {
			return AllowanceParams{}, err
		}
		p, err := v1.convert()
		if err != nil {
			return AllowanceParams{}, err
		}
		if err = p.Validate(); err != nil {
			return AllowanceParams{}, fmt.Errorf("schema 1 body converts to an invalid schema 2: %w", err)
		}
		return p, nil
	}
	return ParseAllowanceParamsSet(body)
}

// ParseAllowanceParamsSet parses and validates a strict schema 2 body: the
// only kind "params set" stores.
func ParseAllowanceParamsSet(body []byte) (AllowanceParams, error) {
	var p AllowanceParams
	if err := strictUnmarshal(body, &p); err != nil {
		return AllowanceParams{}, err
	}
	if err := p.Validate(); err != nil {
		return AllowanceParams{}, err
	}
	return p, nil
}

// resourceParamsV1 is one resource of a schema 1 body (RFC 0012 §2.3's tier
// waterfall). Per-tier arrays were indexed by tier − 1.
type resourceParamsV1 struct {
	Unit           string  `json:"unit"`
	Budget         int64   `json:"budget"`
	SpendCeiling   int64   `json:"spend_ceiling"`
	GrantSharePPM  int64   `json:"grant_share_ppm"`
	Cap            []int64 `json:"cap"`
	Floor          []int64 `json:"floor"`
	RootCap        []int64 `json:"root_cap"`
	ReserveMinPPM  []int64 `json:"reserve_min_ppm"`
	HeadroomPct    []int64 `json:"headroom_pct"`
	ShareMaxPPM    []int64 `json:"share_max_ppm"`
	Borrow         []bool  `json:"borrow"`
	SpillStart     int64   `json:"spill_start"`
	SpillInterval  int64   `json:"spill_interval"`
	TransferFee    int64   `json:"transfer_fee"`
	InboundCap     int64   `json:"inbound_cap"`
	NewKeyFloor    int64   `json:"new_key_floor"`
	ClientSharePPM int64   `json:"client_share_ppm"`
}

// allowanceParamsV1 is a schema 1 body.
type allowanceParamsV1 struct {
	Schema                int                                      `json:"schema"`
	Resources             map[allowance.Resource]*resourceParamsV1 `json:"resources"`
	ClaimExpiryDays       int64                                    `json:"claim_expiry_days"`
	ClaimHalfLifeDays     int64                                    `json:"claim_half_life_days"`
	ClaimRatePPM          int64                                    `json:"claim_rate_ppm"`
	GrantedHalfLifeDays   int64                                    `json:"granted_half_life_days"`
	GrantedRatePPM        int64                                    `json:"granted_rate_ppm"`
	EarnedHalfLifeDays    int64                                    `json:"earned_half_life_days"`
	EarnedRatePPM         int64                                    `json:"earned_rate_ppm"`
	Dust                  int64                                    `json:"dust"`
	TransferableFreeTiers []int64                                  `json:"transferable_free_tiers"`
	PaidTransferable      bool                                     `json:"paid_transferable"`
	TransferDelay         int64                                    `json:"transfer_delay"`
	DormantDays           int64                                    `json:"dormant_days"`
	SpikeX                int64                                    `json:"spike_x"`
	SpikeFloor            int64                                    `json:"spike_floor"`
	TrustResetDays        int64                                    `json:"trust_reset_days"`
}

// convert maps a schema 1 body to schema 2, deterministically:
//
//   - kept as they were: unit, budget, spend_ceiling, grant_share_ppm,
//     spill_start, spill_interval, transfer_fee, inbound_cap, new_key_floor,
//     client_share_ppm and every global parameter but the next one;
//   - transferable_free: true only when transferable_free_tiers named every
//     tier 1–4 (any narrowing converts to false, the safe side);
//   - floor: the signed tier's cap (cap[2], tier 3): what every signed key
//     was offered (the free credit line read it), now bounded by the floor
//     slice over the claimants; at least the signed tier's floor;
//   - cap: the largest of cap[0..3];
//   - anonymous_share_ppm: tier 4's share_max_ppm[3], or 0 when tier 4's
//     cap[3] was 0 (anonymous callers got nothing of the resource);
//   - floor_slice_ppm: 250000;
//   - root_cap, reserve_min_ppm, headroom_pct, borrow and the other tiers'
//     share_max_ppm have no counterpart and are dropped.
func (v1 allowanceParamsV1) convert() (AllowanceParams, error) {
	p := AllowanceParams{
		Schema: AllowanceSchema, Resources: map[allowance.Resource]*ResourceParams{},
		ClaimExpiryDays: v1.ClaimExpiryDays, ClaimHalfLifeDays: v1.ClaimHalfLifeDays, ClaimRatePPM: v1.ClaimRatePPM,
		GrantedHalfLifeDays: v1.GrantedHalfLifeDays, GrantedRatePPM: v1.GrantedRatePPM,
		EarnedHalfLifeDays: v1.EarnedHalfLifeDays, EarnedRatePPM: v1.EarnedRatePPM,
		Dust: v1.Dust, PaidTransferable: v1.PaidTransferable, TransferDelay: v1.TransferDelay,
		DormantDays: v1.DormantDays, SpikeX: v1.SpikeX, SpikeFloor: v1.SpikeFloor, TrustResetDays: v1.TrustResetDays,
	}
	all := len(v1.TransferableFreeTiers) == 4
	for i, t := range v1.TransferableFreeTiers {
		all = all && t == int64(i+1)
	}
	p.TransferableFree = all
	for r, o := range v1.Resources {
		if o == nil || len(o.Cap) != 4 || len(o.Floor) != 4 || len(o.ShareMaxPPM) != 4 {
			return AllowanceParams{}, fmt.Errorf("resources.%s: cap, floor and share_max_ppm have one entry per tier 1–4", r)
		}
		anon := o.ShareMaxPPM[3]
		if o.Cap[3] == 0 {
			anon = 0
		}
		p.Resources[r] = &ResourceParams{
			Unit: o.Unit, Budget: o.Budget, SpendCeiling: o.SpendCeiling, GrantSharePPM: o.GrantSharePPM,
			FloorSlicePPM: defaultFloorSlicePPM, Floor: max(o.Floor[2], o.Cap[2]), Cap: max(o.Cap[0], o.Cap[1], o.Cap[2], o.Cap[3]),
			AnonymousSharePPM: anon, SpillStart: o.SpillStart, SpillInterval: o.SpillInterval,
			TransferFee: o.TransferFee, InboundCap: o.InboundCap, NewKeyFloor: o.NewKeyFloor, ClientSharePPM: o.ClientSharePPM,
		}
	}
	return p, nil
}

// strictUnmarshal decodes exactly one JSON value into v, refusing unknown,
// duplicate and missing keys, null values and trailing data.
func strictUnmarshal(body []byte, v any) error {
	if len(body) > maxParamsBytes {
		return fmt.Errorf("body exceeds %d bytes", maxParamsBytes)
	}
	var shape any
	if err := checkNoDuplicates(body, &shape); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing data after the JSON value")
	}
	var canonical any
	encoded, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if err = json.Unmarshal(encoded, &canonical); err != nil {
		return err
	}
	if path := shapeDiff(shape, canonical, "$"); path != "" {
		return fmt.Errorf("missing or mistyped key at %s", path)
	}
	return nil
}

// checkNoDuplicates walks the token stream and refuses a key repeated in one
// object; it also decodes the generic shape.
func checkNoDuplicates(body []byte, shape *any) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var walk func(depth int) error
	walk = func(depth int) error {
		if depth > 16 {
			return errors.New("nesting deeper than 16")
		}
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		switch d := tok.(type) {
		case json.Delim:
			switch d {
			case '{':
				seen := map[string]bool{}
				for dec.More() {
					key, err := dec.Token()
					if err != nil {
						return err
					}
					k := key.(string)
					if seen[k] {
						return fmt.Errorf("duplicate key %q", k)
					}
					seen[k] = true
					if err = walk(depth + 1); err != nil {
						return err
					}
				}
				_, err = dec.Token()
				return err
			case '[':
				for dec.More() {
					if err = walk(depth + 1); err != nil {
						return err
					}
				}
				_, err = dec.Token()
				return err
			}
		case nil:
			return errors.New("null is not a parameter value")
		}
		return nil
	}
	if err := walk(0); err != nil {
		return err
	}
	return json.Unmarshal(body, shape)
}

// shapeDiff reports the first path where the input's shape (keys, array
// lengths, kinds) differs from the canonical re-encoding, or "".
func shapeDiff(in, canonical any, path string) string {
	switch c := canonical.(type) {
	case map[string]any:
		m, ok := in.(map[string]any)
		if !ok || len(m) != len(c) {
			return path
		}
		keys := make([]string, 0, len(c))
		for k := range c {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			v, ok := m[k]
			if !ok {
				return path + "." + k
			}
			if p := shapeDiff(v, c[k], path+"."+k); p != "" {
				return p
			}
		}
	case []any:
		a, ok := in.([]any)
		if !ok || len(a) != len(c) {
			return path
		}
		for i := range c {
			if p := shapeDiff(a[i], c[i], fmt.Sprintf("%s[%d]", path, i)); p != "" {
				return p
			}
		}
	default:
		if fmt.Sprintf("%T", in) != fmt.Sprintf("%T", canonical) {
			return path
		}
	}
	return ""
}

// Namespace describes a parameter namespace: its compiled-in first version
// and its strict validator. The ledger registers "allowance"; the services
// and trust packages register theirs with RegisterNamespace.
type Namespace struct {
	Version  int64
	Body     func() []byte
	Validate func([]byte) error
}

var (
	namespacesMu sync.RWMutex
	namespaces   = map[string]Namespace{
		AllowanceNamespace: {Version: 0, Body: func() []byte { return DefaultAllowanceParams().Marshal() }, Validate: func(b []byte) error { _, err := ParseAllowanceParamsSet(b); return err }},
	}
)

// RegisterNamespace adds a namespace (services, trust) to every ParamsStore.
func RegisterNamespace(name string, ns Namespace) {
	namespacesMu.Lock()
	defer namespacesMu.Unlock()
	namespaces[name] = ns
}

// ParamsStore is the versioned parameter table (§2.7); it provides
// allowance.ParamsSource. Overrides replace a registered namespace's
// compiled-in version (the board derives allowance version 0 from its
// configured byte budgets).
type ParamsStore struct {
	Overrides map[string]Namespace
}

func (p ParamsStore) namespace(name string) (Namespace, bool) {
	if ns, ok := p.Overrides[name]; ok {
		return ns, true
	}
	namespacesMu.RLock()
	defer namespacesMu.RUnlock()
	ns, ok := namespaces[name]
	return ns, ok
}

// Params is the version in effect at now (Current). A namespace nobody
// registered reads as version 0 with an empty body when nothing is stored,
// so its owner falls back on its own compiled-in defaults.
func (p ParamsStore) Params(ctx context.Context, q allowance.Querier, namespace string, now int64) (int64, []byte, error) {
	v, err := p.Current(ctx, q, namespace, now)
	if err != nil {
		return 0, nil, err
	}
	return v.Version, v.Body, nil
}

// Current is the one selector of the version in effect at now, shared by
// Params, Get(-1) (/api/params "current") and trust runs: the newest stored
// version whose effective_at has passed, unless the compiled-in version is
// newer. Deploying a binary that ships a newer compiled-in version activates
// it with no parameter write (C320a), so an older stored row is superseded,
// never "current". Set numbers stored versions above the compiled-in one, so
// only a compiled-in bump (trust 7 → 10) supersedes a stored row.
func (p ParamsStore) Current(ctx context.Context, q allowance.Querier, namespace string, now int64) (ParamsVersion, error) {
	ns, registered := p.namespace(namespace)
	var v ParamsVersion
	var body string
	err := q.QueryRowContext(ctx, "SELECT version,body,sha256,effective_at,created_at,reason FROM params WHERE namespace=? AND effective_at<=? ORDER BY version DESC LIMIT 1", namespace, now).Scan(&v.Version, &body, &v.SHA256, &v.EffectiveAt, &v.CreatedAt, &v.Reason)
	if errors.Is(err, sql.ErrNoRows) || err == nil && registered && v.Version < ns.Version {
		if !registered {
			return ParamsVersion{Namespace: namespace}, nil
		}
		return compiledIn(namespace, ns, true), nil
	}
	if err != nil {
		return ParamsVersion{}, err
	}
	v.Namespace, v.Body = namespace, json.RawMessage(body)
	return v, nil
}

// compiledIn is the namespace's compiled-in version, with its body when
// withBody (List leaves it out).
func compiledIn(namespace string, ns Namespace, withBody bool) ParamsVersion {
	b := ns.Body()
	sum := sha256.Sum256(b)
	v := ParamsVersion{Namespace: namespace, Version: ns.Version, SHA256: hex.EncodeToString(sum[:]), Reason: "compiled-in defaults", CompiledIn: true}
	if withBody {
		v.Body = b
	}
	return v
}

// ParamsVersion is one stored or compiled-in version, as /api/params shows it.
type ParamsVersion struct {
	Namespace   string          `json:"namespace"`
	Version     int64           `json:"version"`
	Body        json.RawMessage `json:"body"`
	SHA256      string          `json:"sha256"`
	EffectiveAt int64           `json:"effective_at"`
	CreatedAt   int64           `json:"created_at"`
	Reason      string          `json:"reason"`
	CompiledIn  bool            `json:"compiled_in"`
}

// Get reads one version (-1: the one in effect at now, Current).
func (p ParamsStore) Get(ctx context.Context, q allowance.Querier, namespace string, version, now int64) (ParamsVersion, error) {
	ns, ok := p.namespace(namespace)
	if !ok {
		return ParamsVersion{}, &allowance.Err{Code: "invalid_resource"}
	}
	if version < 0 {
		return p.Current(ctx, q, namespace, now)
	}
	var v ParamsVersion
	var body string
	err := q.QueryRowContext(ctx, "SELECT version,body,sha256,effective_at,created_at,reason FROM params WHERE namespace=? AND version=?", namespace, version).Scan(&v.Version, &body, &v.SHA256, &v.EffectiveAt, &v.CreatedAt, &v.Reason)
	if errors.Is(err, sql.ErrNoRows) && version == ns.Version {
		return compiledIn(namespace, ns, true), nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return ParamsVersion{}, ErrNotFound
	}
	if err != nil {
		return ParamsVersion{}, err
	}
	v.Namespace, v.Body = namespace, json.RawMessage(body)
	return v, nil
}

// List is the namespace's versions, newest first: at most 100 stored ones
// and the compiled-in version in version order (a compiled-in version that
// supersedes the stored ones comes first).
func (p ParamsStore) List(ctx context.Context, q allowance.Querier, namespace string) ([]ParamsVersion, error) {
	ns, ok := p.namespace(namespace)
	if !ok {
		return nil, &allowance.Err{Code: "invalid_resource"}
	}
	rows, err := q.QueryContext(ctx, "SELECT version,sha256,effective_at,created_at,reason FROM params WHERE namespace=? ORDER BY version DESC LIMIT 100", namespace)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ParamsVersion
	for rows.Next() {
		v := ParamsVersion{Namespace: namespace}
		if err = rows.Scan(&v.Version, &v.SHA256, &v.EffectiveAt, &v.CreatedAt, &v.Reason); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	out = append(out, compiledIn(namespace, ns, false))
	sort.SliceStable(out, func(i, j int) bool { return out[i].Version > out[j].Version })
	return out, nil
}

// Set validates body and appends it as the next version. The stored body is
// the compacted input; effective must not be in the past.
func (p ParamsStore) Set(ctx context.Context, q allowance.Querier, namespace string, body []byte, actor, reason string, effective, now int64) (int64, error) {
	ns, ok := p.namespace(namespace)
	if !ok {
		return 0, fmt.Errorf("unknown parameter namespace %q", namespace)
	}
	if reason == "" || len(reason) > 512 {
		return 0, errors.New("a public reason of 1–512 bytes is required")
	}
	if effective < now {
		effective = now
	}
	if ns.Validate == nil {
		return 0, fmt.Errorf("namespace %q has no validator", namespace)
	}
	if err := ns.Validate(body); err != nil {
		return 0, fmt.Errorf("invalid %s parameters: %w", namespace, err)
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, body); err != nil {
		return 0, err
	}
	var latest sql.NullInt64
	if err := q.QueryRowContext(ctx, "SELECT max(version) FROM params WHERE namespace=?", namespace).Scan(&latest); err != nil {
		return 0, err
	}
	version := ns.Version + 1
	if latest.Valid && latest.Int64 >= version {
		version = latest.Int64 + 1
	}
	sum := sha256.Sum256(compact.Bytes())
	_, err := q.ExecContext(ctx, "INSERT INTO params(namespace,version,body,sha256,effective_at,created_at,actor,reason) VALUES(?,?,?,?,?,?,?,?)", namespace, version, compact.String(), hex.EncodeToString(sum[:]), effective, now, actor, reason)
	return version, err
}

var _ allowance.ParamsSource = ParamsStore{}
