package ledger

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"swarmmemo/internal/allowance"
)

// RFC 0021 §12's share rule: table tests on the pure functions (OpenDay,
// the entitlement, draw and spill, adjust) and real-ledger tests of its
// properties (the floor for everyone, shares by standing, each root once,
// the cap, sybils only thinning the floor, the levers, spill once, the
// schema 1 conversion).

const day0 = int64(20701) // 2026-09-06, 00:00 UTC = 1788566400

func noLevers() allowance.Levers { return allowance.Levers{AnonymousSharePPM: -1} }

func testResource(budget int64) *ResourceParams {
	rp := *DefaultAllowanceParams().Resources[allowance.PostBytes]
	rp.Budget, rp.SpendCeiling, rp.InboundCap = budget, 2*budget, budget
	rp.Floor, rp.Cap = 0, budget
	return &rp
}

func sizes(d dayState) [3]int64 {
	var s [3]int64
	for i := range d.Slices {
		s[i] = d.Slices[i].Size
	}
	return s
}

func TestOpenDaySlices(t *testing.T) {
	prev := func(claimants, expected, weight, expectedW int64) *dayState {
		d := &dayState{}
		d.Slices[sliceFloor].Claimants, d.Slices[sliceFloor].Expected = claimants, expected
		d.Slices[sliceStanding].Weight, d.Slices[sliceStanding].Expected = weight, expectedW
		return d
	}
	cases := []struct {
		name        string
		grant       int64
		prev        *dayState
		levers      allowance.Levers
		want        [3]int64
		expected    [2]int64 // floor's expected claimants, standing's expected Σ cents
		unallocated int64
	}{
		{"fresh", 0, nil, noLevers(), [3]int64{0, 250, 750}, [2]int64{}, 0},
		// The grant slice comes off the top; the floor slice is a quarter of
		// the rest.
		{"grant share", 100_000, nil, noLevers(), [3]int64{100, 225, 675}, [2]int64{}, 0},
		// Demand rises at once.
		{"demand rises", 0, prev(300, 100, 900, 100), noLevers(), [3]int64{0, 250, 750}, [2]int64{300, 900}, 0},
		// Demand falls by half a day.
		{"demand falls by half", 0, prev(0, 400, 100, 1000), noLevers(), [3]int64{0, 250, 750}, [2]int64{200, 550}, 0},
		// cut-budget by half: every slice is of the effective budget.
		{"cut budget", 0, nil, allowance.Levers{AnonymousSharePPM: -1, BudgetCutPPM: map[allowance.Resource]int64{allowance.PostBytes: 500_000}}, [3]int64{0, 125, 375}, [2]int64{}, 500},
		// The other levers act on entitlements and draws, not on sizes.
		{"signed only", 0, nil, allowance.Levers{AnonymousSharePPM: 0, SignedOnly: true, ProvenOnly: true}, [3]int64{0, 250, 750}, [2]int64{}, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rp := testResource(1000)
			rp.GrantSharePPM = c.grant
			d := computeOpen(allowance.PostBytes, day0, rp, c.levers, c.prev, 0, day0*86400)
			if got := sizes(d); got != c.want {
				t.Fatalf("sizes %v, want %v", got, c.want)
			}
			if got := [2]int64{d.Slices[sliceFloor].Expected, d.Slices[sliceStanding].Expected}; got != c.expected {
				t.Fatalf("expected %v, want %v", got, c.expected)
			}
			if d.Unallocated != c.unallocated || d.allocated()+d.Unallocated != d.Budget {
				t.Fatalf("unallocated %d (expected %d), allocated %d, budget %d", d.Unallocated, c.unallocated, d.allocated(), d.Budget)
			}
		})
	}
}

func TestEntitlementTable(t *testing.T) {
	rp := testResource(1000) // floor slice 250, standing slice 750
	rp.Floor, rp.Cap, rp.NewKeyFloor = 50, 400, 5
	d := computeOpen(allowance.PostBytes, day0, rp, noLevers(), nil, 0, day0*86400)
	st := func(band allowance.Band, cents int64) allowance.Standing {
		return allowance.Standing{Band: band, Cents: cents, ShareCents: cents, Root: "r"}
	}
	signed, proven, anon := allowance.BandSigned, allowance.BandProven, allowance.BandAnonymous
	cases := []struct {
		name                string
		claimants, expected int64 // floor slice: today's claimants, expected claimants
		weight, expectedW   int64 // standing slice: today's Σ cents, expected Σ cents
		st                  allowance.Standing
		root                rootDay
		levers              allowance.Levers
		floor, standing     int64
	}{
		{"alone: the floor", 0, 0, 0, 0, st(signed, 0), rootDay{}, noLevers(), 50, 0},
		{"anonymous: the same floor", 0, 0, 0, 0, st(anon, 0), rootDay{}, noLevers(), 50, 0},
		{"water left: the whole floor however many claim", 9, 25, 0, 0, st(signed, 0), rootDay{}, noLevers(), 50, 0},
		{"a dry slice thins it past slice/floor claimants", 9, 0, 0, 0, st(signed, 0), rootDay{}, noLevers(), 25, 0},
		{"a dry slice: expected claimants thin it before they arrive", 0, 25, 0, 0, st(signed, 0), rootDay{}, noLevers(), 10, 0},
		{"standing alone: the slice, capped", 0, 0, 0, 0, st(proven, 300), rootDay{}, noLevers(), 50, 350},
		{"shares by standing", 0, 0, 0, 1500, st(proven, 300), rootDay{}, noLevers(), 50, 150},
		{"today's roots count", 0, 0, 1200, 0, st(proven, 300), rootDay{}, noLevers(), 50, 150},
		{"a root's second claim adds no weight", 0, 0, 1200, 0, st(proven, 300), rootDay{Claims: 1, Standing: 100}, noLevers(), 50, 87},
		{"each root once: its share given", 0, 0, 1200, 0, st(proven, 300), rootDay{Claims: 1, Standing: 187}, noLevers(), 50, 0},
		{"new key paused", 0, 0, 0, 0, allowance.Standing{Band: signed, ShareCents: 300, Root: "r", NewKey: true}, rootDay{}, allowance.Levers{AnonymousSharePPM: -1, PauseNewKeys: true}, 5, 0},
		{"signed only: anonymous nothing", 0, 0, 0, 0, st(anon, 0), rootDay{}, allowance.Levers{AnonymousSharePPM: -1, SignedOnly: true}, 0, 0},
		{"proven only: signed nothing", 0, 0, 0, 0, st(signed, 50), rootDay{}, allowance.Levers{AnonymousSharePPM: -1, ProvenOnly: true}, 0, 0},
		{"proven only: proven keeps both", 0, 0, 0, 0, st(proven, 300), rootDay{}, allowance.Levers{AnonymousSharePPM: -1, ProvenOnly: true}, 50, 350},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dd := d
			dd.Slices[sliceFloor].Claimants, dd.Slices[sliceFloor].Expected = c.claimants, c.expected
			dd.Slices[sliceStanding].Weight, dd.Slices[sliceStanding].Expected = c.weight, c.expectedW
			if strings.HasPrefix(c.name, "a dry slice") {
				dd.Slices[sliceFloor].Claimed = dd.Slices[sliceFloor].Size - 5 // spent down to 5
			}
			if f, s := entitlement(&dd, rp, c.levers, c.st, c.root); f != c.floor || s != c.standing {
				t.Fatalf("floor %d standing %d, want %d %d", f, s, c.floor, c.standing)
			}
		})
	}
	// A resource whose anonymous share is 0 gives anonymous subjects nothing.
	rp.AnonymousSharePPM = 0
	if f, s := entitlement(&d, rp, noLevers(), st(anon, 0), rootDay{}); f != 0 || s != 0 {
		t.Fatalf("anonymous share 0: %d %d", f, s)
	}
}

func TestDrawSpillOnceTable(t *testing.T) {
	rp := testResource(86400) // floor slice 21600, standing 64800
	start := day0 * 86400
	cases := []struct {
		name   string
		at     int64
		origin int64
		want   int64
		got    int64
		// claimed and lent of the floor and standing slices after the draw
		floor, standing [2]int64
	}{
		{"own water first", start, originFloor, 1000, 1000, [2]int64{1000, 0}, [2]int64{0, 0}},
		{"at midnight nothing spills", start, originFloor, 30000, 21600, [2]int64{21600, 0}, [2]int64{0, 0}},
		{"before spill_start nothing spills", start + 3599, originStanding, 70000, 64800, [2]int64{0, 0}, [2]int64{64800, 0}},
		// At 01:00, f = 41666 ppm: the standing slice keeps
		// ceil(64800 × 958334 / 1e6) = 62101 and lends 2699.
		{"first boundary", start + 3600, originFloor, 30000, 24299, [2]int64{21600, 0}, [2]int64{0, 2699}},
		// At noon half of the other slice's unspent water spills.
		{"noon", start + 12*3600, originAnonymous, 60000, 54000, [2]int64{21600, 0}, [2]int64{0, 32400}},
		{"standing borrows the floor's", start + 12*3600, originStanding, 80000, 75600, [2]int64{0, 10800}, [2]int64{64800, 0}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := computeOpen(allowance.PostBytes, day0, rp, noLevers(), nil, 0, start)
			if got := drawable(&d, rp, c.origin, c.at); got < c.got || c.got < c.want && got != c.got {
				t.Fatalf("drawable %d, drew %d", got, c.got)
			}
			if got := draw(&d, rp, c.origin, c.want, c.at); got != c.got {
				t.Fatalf("drew %d, want %d", got, c.got)
			}
			f, s := d.Slices[sliceFloor], d.Slices[sliceStanding]
			if [2]int64{f.Claimed, f.Lent} != c.floor || [2]int64{s.Claimed, s.Lent} != c.standing || f.Borrowed != s.Lent || s.Borrowed != f.Lent {
				t.Fatalf("floor %+v standing %+v", f, s)
			}
			if c.origin == originAnonymous && d.Anon.Claimed != c.got {
				t.Fatalf("anonymous account %d, drew %d", d.Anon.Claimed, c.got)
			}
			// Undrawing returns borrowed water first, then the slice's own.
			undraw(&d, c.origin, c.got)
			if d.Slices != computeOpen(allowance.PostBytes, day0, rp, noLevers(), nil, 0, start).Slices || d.Anon.Claimed != 0 {
				t.Fatalf("undraw left %+v", d.Slices)
			}
		})
	}
}

func TestAdjustShrinksAndRestores(t *testing.T) {
	rp := testResource(1000)
	d := computeOpen(allowance.PostBytes, day0, rp, noLevers(), nil, 0, day0*86400)
	draw(&d, rp, originStanding, 500, day0*86400) // the standing slice issued 500 of its 750
	cut := allowance.Levers{AnonymousSharePPM: -1, BudgetCutPPM: map[allowance.Resource]int64{allowance.PostBytes: 500_000}}
	if !adjust(&d, rp, cut) {
		t.Fatal("cut-budget changed nothing")
	}
	// Target 500: the standing slice keeps what it issued (500), the floor
	// slice gives up all its unissued water. Issued units are untouched.
	if got := sizes(d); got != ([3]int64{0, 0, 500}) || d.Unallocated != 500 {
		t.Fatalf("after cut: %v, unallocated %d", got, d.Unallocated)
	}
	if !adjust(&d, rp, noLevers()) {
		t.Fatal("release changed nothing")
	}
	if got := sizes(d); got != ([3]int64{0, 250, 750}) || d.Unallocated != 0 {
		t.Fatalf("after release: %v, unallocated %d", got, d.Unallocated)
	}
	if adjust(&d, rp, noLevers()) {
		t.Fatal("adjust is not idempotent")
	}
}

// claimAll has every subject claim (a spend of nothing) and returns each
// one's balance afterwards.
func (h *harness) claimAll(subjects []allowance.Subject) []Balance {
	h.t.Helper()
	out := make([]Balance, len(subjects))
	for i, s := range subjects {
		if err := h.spend(s, 0); err != nil {
			h.t.Fatalf("%s: %v", s.ID, err)
		}
		out[i] = h.balance(s)
	}
	return out
}

// RFC 0021 §12 on the real ledger, with TestAnchorAllowanceShares' numbers:
// B = 64 MiB, floor 64 KiB, cap 16 MiB, a quarter of B the floor slice.
func shareRuleParams() AllowanceParams {
	p := DefaultAllowanceParams()
	rp := p.Resources[allowance.PostBytes]
	rp.Budget, rp.SpendCeiling, rp.Floor, rp.Cap, rp.FloorSlicePPM = 64<<20, 128<<20, 64<<10, 16<<20, 250_000
	return p
}

// world is 200 signed accounts, 35 of them with standing from 20¢ to 700¢
// (each its own root), and 50 anonymous prefixes.
func world(extra ...allowance.Subject) (subjects []allowance.Subject, cents []int64) {
	for i := 0; i < 200; i++ {
		var c int64
		id := fmt.Sprintf("acct%d", i)
		if i < 35 {
			c = 20 + int64(i)*20
			id = fmt.Sprintf("c%d-acct%d", c, i)
		}
		subjects, cents = append(subjects, signedSubject(id)), append(cents, c)
	}
	for i := 0; i < 50; i++ {
		subjects, cents = append(subjects, anonSubject(fmt.Sprintf("net%d", i))), append(cents, 0)
	}
	for _, s := range extra {
		var c int64
		for _, seg := range strings.Split(s.ID, "-") {
			fmt.Sscanf(seg, "c%d", &c)
		}
		subjects, cents = append(subjects, s), append(cents, c)
	}
	return subjects, cents
}

// warmDay claims for every subject on two days and returns the second day's
// balances, when yesterday's demand is the day's expectation.
func warmDay(h *harness, subjects []allowance.Subject) []Balance {
	h.claimAll(subjects)
	h.now += 86400
	return h.claimAll(subjects)
}

func dayEntitled(h *harness) int64 {
	return h.count("SELECT coalesce(sum(granted),0) FROM allowance_claims WHERE resource='post_bytes' AND day=?", h.now/86400)
}

func TestShareRuleSybilsOnlyThinTheFloor(t *testing.T) {
	const mib, kib = int64(1) << 20, int64(1) << 10
	const B, f, standingSlice, cap = 64 * mib, 64 * kib, 48 * mib, 16 * mib
	h := newHarness(t, shareRuleParams())
	subjects, cents := world()
	var total int64
	for _, c := range cents {
		total += c
	}
	base := warmDay(h, subjects)
	for i, b := range base {
		want := min(cap-f, mulDiv(standingSlice, cents[i], total))
		if b.FloorPart != f || b.StandingPart != want || b.Entitlement != f+want {
			t.Fatalf("%s (%d¢): floor %d standing %d, want %d %d", subjects[i].ID, cents[i], b.FloorPart, b.StandingPart, f, want)
		}
	}
	if got := dayEntitled(h); got > B {
		t.Fatalf("the day's entitlements %d exceed the budget %d", got, B)
	}
	t.Logf("250 claimants: floor %d KiB each; 700¢ gets %d KiB of standing", f>>10, base[34].StandingPart>>10)

	// 1,000 fresh keys join. While the floor slice holds water every
	// claimant still gets the whole floor (generous until constrained,
	// C320c: claims draw nothing), and the standing parts stay.
	for i := 0; i < 1000; i++ {
		subjects = append(subjects, signedSubject(fmt.Sprintf("fresh%d", i)))
	}
	h.now += 86400
	sybil := warmDay(h, subjects)
	for i, b := range sybil {
		if b.FloorPart != f {
			t.Fatalf("%s: floor %d, want %d", subjects[i].ID, b.FloorPart, f)
		}
		if i < len(base) && b.StandingPart != base[i].StandingPart {
			t.Fatalf("%s: sybils moved its standing part from %d to %d", subjects[i].ID, base[i].StandingPart, b.StandingPart)
		}
	}
	// Once they spend the floor slice dry, the floor thins to the slice over
	// the expected claimants (64 → 13 KiB), and the day's spend stays B.
	day := h.now / 86400
	if err := h.do(func(q *sql.Tx) error {
		_, err := q.Exec("UPDATE allowance_pools SET claimed=size-lent WHERE resource='post_bytes' AND day=? AND tier=?", day, sliceFloor)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	late := h.claimAll([]allowance.Subject{signedSubject("late-fresh")})[0]
	thin := (B / 4) / 1251
	if late.FloorPart != thin || thin>>10 != 13 {
		t.Fatalf("a claimant after the floor slice ran dry: floor %d, want %d (13 KiB)", late.FloorPart, thin)
	}
}

// A ring's 600¢ buys the same standing part on one key as split over 50 keys
// of different roots, beyond rounding.
func TestShareRuleSplittingStandingGainsNothing(t *testing.T) {
	one := newHarness(t, shareRuleParams())
	s1, _ := world(signedSubject("c600-ring"))
	a := warmDay(one, s1)
	var ring []allowance.Subject
	for k := 0; k < 50; k++ {
		ring = append(ring, signedSubject(fmt.Sprintf("c12-ring%d", k)))
	}
	split := newHarness(t, shareRuleParams())
	s2, _ := world(ring...)
	b := warmDay(split, s2)
	single := a[len(a)-1].StandingPart
	var spread int64
	for _, x := range b[len(b)-50:] {
		spread += x.StandingPart
	}
	t.Logf("600¢ buys %d KiB of standing on one key, %d KiB over 50", single>>10, spread>>10)
	if spread > single+50 || spread < single-50 {
		t.Fatalf("splitting 600¢ over 50 keys: %d, one key %d", spread, single)
	}
}

// Two accounts of one root share the root's one standing share; a claimant
// is never above the cap.
func TestShareRuleEachRootOnceUnderTheCap(t *testing.T) {
	p := smallParams()
	rp := p.Resources[allowance.PostBytes]
	rp.Floor, rp.Cap, rp.FloorSlicePPM = 0, 1000, 0 // all 1,000 is the standing slice
	h := newHarness(t, p)
	subjects := []allowance.Subject{signedSubject("root-r-c100-a"), signedSubject("root-r-c100-b"), signedSubject("c100-x")}
	got := warmDay(h, subjects)
	if got[0].StandingPart != 500 || got[1].StandingPart != 0 || got[2].StandingPart != 500 {
		t.Fatalf("root r's accounts %d + %d, root x %d; want 500 + 0, 500", got[0].StandingPart, got[1].StandingPart, got[2].StandingPart)
	}
	// One claimant alone with all the standing: the whole slice, capped.
	rp.Cap = 300
	h2 := newHarness(t, p)
	if b := h2.claimAll([]allowance.Subject{signedSubject("c5000-whale")})[0]; b.Entitlement != 300 || b.StandingPart != 300 {
		t.Fatalf("a claimant above the cap: %+v", b)
	}
	checkInvariants(t, h.db, h.p)
}

// Unused water spills once: at midnight a flood of floor-only claimants
// stops at the floor slice and leaves the standing slice to its claimants;
// later in the day the other slice's unspent water is drawn.
func TestShareRuleSpillOnce(t *testing.T) {
	h := newHarness(t, smallParams()) // floor slice 500, standing 500
	for i := 0; i < 20; i++ {
		s := signedSubject(fmt.Sprintf("fresh%d", i))
		if i%2 == 0 {
			s = anonSubject(fmt.Sprintf("flood%d", i))
		}
		for _, n := range []int64{100, 10, 1} {
			for h.spend(s, n) == nil {
			}
		}
	}
	d, _, _ := loadDay(ctx, h.db, allowance.PostBytes, day0)
	if d.Slices[sliceFloor].avail() != 0 || d.Slices[sliceStanding].Claimed != 0 || d.Slices[sliceStanding].Lent != 0 {
		t.Fatalf("the flood reached the standing slice: %+v", d.Slices)
	}
	if got := code(h.spend(signedSubject("late"), 1)); got != "global_quota_exhausted" {
		t.Fatalf("a late floor-only claimant at midnight: %s", got)
	}
	// Standing holders draw their slice in full.
	for _, s := range []allowance.Subject{signedSubject("c500-x"), signedSubject("c500-y")} {
		if err := h.spend(s, 150); err != nil {
			t.Fatalf("%s: %v", s.ID, err)
		}
	}
	// At noon half the standing slice's unspent 200 may be lent.
	h.now += 12 * 3600
	for i := 0; i < 20; i++ {
		for h.spend(signedSubject(fmt.Sprintf("late%d", i)), 10) == nil {
		}
	}
	d, _, _ = loadDay(ctx, h.db, allowance.PostBytes, day0)
	if s := d.Slices[sliceStanding]; s.Lent != 100 || d.Slices[sliceFloor].Borrowed != 100 {
		t.Fatalf("at noon the standing slice lent %d, want 100: %+v", s.Lent, d.Slices)
	}
	if d.SpentNonpaid > 1000 {
		t.Fatalf("spent %d of a 1000 budget", d.SpentNonpaid)
	}
	checkInvariants(t, h.db, h.p)
}

func TestShareRuleLevers(t *testing.T) {
	h := newHarness(t, smallParams())
	// proven-only: below the proven band nothing, the proven keep their share.
	h.levers.lv.ProvenOnly = true
	if got := code(h.spend(signedSubject("plain"), 1)); got != "quota_exhausted" {
		t.Fatalf("signed under proven-only: %s", got)
	}
	if got := code(h.spend(anonSubject("a"), 1)); got != "quota_exhausted" {
		t.Fatalf("anonymous under proven-only: %s", got)
	}
	if err := h.spend(signedSubject("c200-p"), 1); err != nil {
		t.Fatalf("proven under proven-only: %v", err)
	}
	h.levers.lv.ProvenOnly = false
	// signed-only: a new anonymous subject gets nothing; an issued anonymous
	// share stops at once.
	if err := h.spend(anonSubject("b"), 1); err != nil {
		t.Fatal(err)
	}
	h.levers.lv.SignedOnly = true
	if got := code(h.spend(anonSubject("b"), 1)); got != "global_quota_exhausted" {
		t.Fatalf("an issued anonymous share under signed-only: %s", got)
	}
	if got := code(h.spend(anonSubject("c"), 1)); got != "quota_exhausted" {
		t.Fatalf("a new anonymous subject under signed-only: %s", got)
	}
	if err := h.spend(signedSubject("s"), 1); err != nil {
		t.Fatalf("signed under signed-only: %v", err)
	}
	h.levers.lv.SignedOnly = false
	// anonymous-shrink: anonymous lots together draw at most the lever's
	// share of the budget (posting has no hourly release: its parameters'
	// anonymous share is 100%).
	h.levers.lv.AnonymousSharePPM = 5_000 // 5 of 1,000
	if err := h.spend(anonSubject("b"), 4); err != nil {
		t.Fatalf("within the shrunk share: %v", err)
	}
	if got := code(h.spend(anonSubject("d"), 1)); got != "global_quota_exhausted" {
		t.Fatalf("past the shrunk share: %s", got)
	}
	h.levers.lv.AnonymousSharePPM = -1
	// pause-new-keys: a new key gets new_key_floor.
	h.p.Resources[allowance.PostBytes].NewKeyFloor = 7
	h.levers.lv.PauseNewKeys = true
	if b := h.balance(signedSubject("new-c300-k")); b.Entitlement != 7 {
		t.Fatalf("a new key under pause-new-keys: %+v", b)
	}
	if b := h.balance(signedSubject("old-k")); b.Entitlement == 7 {
		t.Fatalf("an old key under pause-new-keys: %+v", b)
	}
	checkInvariants(t, h.db, h.p)
}

// schema1Body is a schema 1 body: the RFC 0012 defaults, with credit's
// anonymous share at 10% and posting's transferable tiers as given.
func schema1Body(t testing.TB, transferable []int64) []byte {
	const mib = 1 << 20
	res := func(unit string, budget, ceiling, fee, inbound int64, cap, floor, share []int64) *resourceParamsV1 {
		return &resourceParamsV1{Unit: unit, Budget: budget, SpendCeiling: ceiling, GrantSharePPM: 0, Cap: cap, Floor: floor,
			RootCap: []int64{budget, budget, budget, budget}, ReserveMinPPM: []int64{100_000, 100_000, 200_000}, HeadroomPct: []int64{50, 50, 50},
			ShareMaxPPM: share, Borrow: []bool{true, true, true}, SpillStart: 3600, SpillInterval: 3600, TransferFee: fee, InboundCap: inbound, ClientSharePPM: ppm}
	}
	v1 := allowanceParamsV1{
		Schema: 1,
		Resources: map[allowance.Resource]*resourceParamsV1{
			allowance.PostBytes:   res("byte", 64*mib, 128*mib, 256, 64*mib, []int64{16 * mib, 8 * mib, 4 * mib, 4 * mib}, []int64{64 << 10, 64 << 10, 64 << 10, 16 << 10}, []int64{ppm, ppm, ppm, ppm}),
			allowance.MemoryBytes: res("byte", 16*mib, 32*mib, 256, 16*mib, []int64{4 * mib, 2 * mib, 1 * mib, 1 * mib}, []int64{16 << 10, 16 << 10, 16 << 10, 16 << 10}, []int64{ppm, ppm, ppm, 0}),
			allowance.Credit:      res("credit", 10000, 10000, 1, 0, []int64{4000, 2000, 1000, 20}, []int64{16, 16, 16, 20}, []int64{ppm, ppm, ppm, 100_000}),
		},
		GrantedHalfLifeDays: 14, GrantedRatePPM: RatePPM(14), EarnedHalfLifeDays: 30, EarnedRatePPM: RatePPM(30),
		Dust: 64, TransferableFreeTiers: transferable, PaidTransferable: true,
		TransferDelay: 48 * 3600, DormantDays: 30, SpikeX: 4, SpikeFloor: 8, TrustResetDays: 30,
	}
	b, err := json.Marshal(v1)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSchema1Converts(t *testing.T) {
	p, err := ParseAllowanceParams(schema1Body(t, []int64{1, 2, 3, 4}))
	if err != nil {
		t.Fatal(err)
	}
	const mib = 1 << 20
	want := DefaultAllowanceParams()
	// The schema 1 body's budgets and anonymous shares, not the doubled
	// defaults (C320c): a conversion keeps what was set.
	post, mem := want.Resources[allowance.PostBytes], want.Resources[allowance.MemoryBytes]
	post.Budget, post.SpendCeiling, post.InboundCap = 64*mib, 128*mib, 64*mib
	mem.Budget, mem.SpendCeiling, mem.InboundCap, mem.AnonymousSharePPM = 16*mib, 32*mib, 16*mib, 0
	want.Resources[allowance.MemoryBytes].Cap = 4 * mib
	// The floor is the signed tier's cap (cap[2]): what each signed key was offered.
	want.Resources[allowance.MemoryBytes].Floor = 1 * mib
	want.Resources[allowance.PostBytes].Floor = 4 * mib
	c := want.Resources[allowance.Credit]
	c.Budget, c.SpendCeiling, c.Floor, c.Cap, c.AnonymousSharePPM, c.InboundCap = 10000, 10000, 1000, 4000, 100_000, 0
	if string(p.Marshal()) != string(want.Marshal()) {
		t.Fatalf("schema 1 converts to\n%s\nwant\n%s", p.Marshal(), want.Marshal())
	}
	// A narrowed transferable_free_tiers converts to false.
	if p, err = ParseAllowanceParams(schema1Body(t, []int64{1, 2})); err != nil || p.TransferableFree {
		t.Fatalf("narrowed transfers: %v %v", p.TransferableFree, err)
	}
	// params set takes schema 2 only; schema 1 still reads.
	if _, err = ParseAllowanceParamsSet(schema1Body(t, []int64{1, 2, 3, 4})); err == nil {
		t.Fatal("a schema 1 body was accepted for params set")
	}
	h := newHarness(t, smallParams())
	if _, err = (ParamsStore{}).Set(ctx, h.db, AllowanceNamespace, schema1Body(t, []int64{1, 2, 3, 4}), "steward", "old", h.now, h.now); err == nil {
		t.Fatal("params set stored a schema 1 body")
	}
	// A stored schema 1 version runs the share rule.
	if _, err = h.db.Exec("INSERT INTO params(namespace,version,body,sha256,effective_at,created_at,actor,reason) VALUES('allowance',1,?,'x',0,0,'steward','old')", string(schema1Body(t, []int64{1, 2, 3, 4}))); err != nil {
		t.Fatal(err)
	}
	l := New(Config{Classifier: standingClassifier{}})
	var b Balance
	if err = h.do(func(q *sql.Tx) error {
		if _, err := l.Spend(ctx, q, signedSubject("alice"), allowance.PostBytes, 1, Ref{Service: "board", Op: "post"}, h.now); err != nil {
			return err
		}
		b, err = l.Balance(ctx, q, signedSubject("alice"), allowance.PostBytes, h.now)
		return err
	}); err != nil || b.ParamsVersion != 1 || b.Entitlement != 4<<20 {
		t.Fatalf("a stored schema 1 version: %+v %v", b, err)
	}
}

// A day opened before the share rule (five tier rows) folds into the slices
// without handing out again what was spent, and is rewritten on the next
// write.
func TestLegacyDayFolds(t *testing.T) {
	h := newHarness(t, smallParams())
	if _, err := h.db.Exec("INSERT INTO allowance_days(resource,day,budget,budget_effective,unallocated,spent_nonpaid,spent_paid,spill_done_at,opened_at,params_version) VALUES('post_bytes',?,1000,1000,0,300,0,0,?,0)", day0, h.now); err != nil {
		t.Fatal(err)
	}
	for tier, row := range [][3]int64{{0, 0, 0}, {100, 0, 0}, {100, 50, 0}, {200, 150, 50}, {600, 100, 0}} {
		if _, err := h.db.Exec("INSERT INTO allowance_pools(resource,day,tier,size,want,spill_in,spill_out,claimed,lent,borrowed,expected_units,expected_weight,claimed_weight,claimants) VALUES('post_bytes',?,?,?,0,0,0,?,?,0,0,0,0,0)", day0, tier, row[0], row[1], row[2]); err != nil {
			t.Fatal(err)
		}
	}
	d, _, err := loadDay(ctx, h.db, allowance.PostBytes, day0)
	if err != nil || !d.legacy || d.Slices[sliceStanding].Size != 1000 || d.Slices[sliceStanding].Claimed != 350 || d.Anon.Claimed != 100 {
		t.Fatalf("folded %+v %v", d, err)
	}
	if err = h.spend(signedSubject("alice"), 10); err != nil {
		t.Fatal(err)
	}
	if n := h.count("SELECT count(*) FROM allowance_pools WHERE day=?", day0); n != 4 {
		t.Fatalf("%d pool rows after the first write", n)
	}
	d, _, _ = loadDay(ctx, h.db, allowance.PostBytes, day0)
	// adjust brought the standing slice down to its 500 (350 of it spent)
	// and gave the floor slice its 500.
	if d.legacy || d.allocated() != 1000 || d.Slices[sliceStanding].Size != 500 || d.Slices[sliceStanding].Claimed != 350 || d.Slices[sliceFloor].Size != 500 || d.Slices[sliceFloor].Claimed != 10 {
		t.Fatalf("rewritten %+v", d)
	}
}
