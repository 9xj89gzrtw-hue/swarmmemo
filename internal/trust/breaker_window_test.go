package trust

import (
	"bytes"
	"context"
	"strconv"
	"testing"
)

// C338, RFC 0021 §2.2: version 11 sizes an account-change breaker's trust
// window by its reason (breaker_trust_days): a key rotation or a dormant
// key's return silences the account's judgements for 30 days, a proof link
// or unlink for 7, and a spike in outbound credit transfers not at all. The
// conserved flow (§2.1) bounds what any judgement passes, so a shorter
// window never lets a sybil ring hold more than its backers' offers.

// breaker adds an account_breakers row for name: reason, started daysAgo,
// trust_until 30 days later (the ledger's trust_reset_days).
func (b *builder) breaker(name, reason string, daysAgo int64) *builder {
	b.snap.Breakers = append(b.snap.Breakers, Record{Type: "breaker", Account: acct(name), Kind: reason, StartedAt: ago(daysAgo) + 60, TrustUntil: ago(daysAgo) + 60 + 30*day})
	return b
}

// Version 11 is version 10 plus breaker_trust_days, refused before it; an
// unknown reason or a window past a year is refused.
func TestBreakerParamsV11(t *testing.T) {
	d := BreakerParams()
	if d.Version != BreakerVersion || DefaultVersion != DomainFloorOnceVersion || DefaultParams().Version != DomainFloorOnceVersion {
		t.Fatalf("default version %d", d.Version)
	}
	if _, err := ParseParams(BreakerVersion, d.Body()); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseParams(PassVersion, d.Body()); err == nil {
		t.Fatal("version 10 accepted breaker_trust_days")
	}
	if d.BreakerTrustDays, d.Version = nil, PassVersion; !bytes.Equal(d.Body(), PassParams().Body()) {
		t.Fatal("version 11 differs from version 10 in more than breaker_trust_days")
	}
	for _, bad := range []map[string]int64{{"standing.challenge": 1}, {"spike": 366}, {"identity.link": -1}} {
		p := DefaultParams()
		p.BreakerTrustDays = bad
		if err := p.Validate(); err == nil {
			t.Errorf("breaker_trust_days %v accepted", bad)
		}
	}
	// A reason the parameters do not name keeps the row's trust_until.
	r := Record{Kind: "", StartedAt: 100, TrustUntil: 100 + 30*day}
	if got := DefaultParams().BreakerUntil(r); got != r.TrustUntil {
		t.Errorf("an unnamed reason holds until %d, want trust_until", got)
	}
	r.Kind = "identity.link"
	if got := DefaultParams().BreakerUntil(r); got != 100+7*day {
		t.Errorf("identity.link holds until %d, want started_at + 7 days", got)
	}
}

// ringOf adds k fresh ring keys that rate each other's work at 100.
func ringOf(b *builder, k int) []string {
	var m []string
	for i := 0; i < k; i++ {
		m = append(m, "sybil"+strconv.Itoa(i))
	}
	for _, x := range m {
		for _, y := range m {
			if x != y {
				b.review(x, y, 100, "paid_use", 1).vouch(x, y, 1)
			}
		}
	}
	return m
}

// Sybil after link: an account links a fresh priced proof (a domain), then
// vouches for, accepts and rates a ring of 20 fresh keys at 100. Inside the
// 7-day window the ring holds 0; after it, at most the linker's offer (what
// it holds above node_cap topped up to its pass share), which the linker
// gives up; in no case more than version 10 with no breaker at all.
func TestBreakerSybilAfterLink(t *testing.T) {
	for _, c := range []struct {
		name  string
		paid  int64 // money paid on top of the domain
		since int64 // days since the link
		open  bool  // the window has passed
	}{
		{"domain only, linked 2 days ago", 0, 2, false},
		{"domain only, linked 6 days ago", 0, 6, false},
		{"domain only, linked 8 days ago", 0, 8, true},
		{"domain and 1,500¢, linked 1 day ago", 1500, 1, false},
		{"domain and 1,500¢, linked 10 days ago", 1500, 10, true},
	} {
		build := func(params Params, withBreaker bool) Output {
			b := newBuilder()
			b.snap.Params = params
			b.domain("linker", "fresh.example", 400, 5000)
			b.snap.Proofs[len(b.snap.Proofs)-1].CreatedAt = ago(c.since)
			if c.paid > 0 {
				b.pay("linker", c.paid, 30)
			}
			if withBreaker {
				b.breaker("linker", "identity.link", c.since)
			}
			ring := ringOf(b, 20)
			for i, s := range ring {
				d := min(c.since, 1+int64(i%3)) // judged after the link
				b.vouch("linker", s, d).accept("linker", s, d).review("linker", s, 100, "work", d)
			}
			return compute(t, b)
		}
		// The ring holds what judgements passed it plus the time present
		// the linker's answers (its judgements) back with its direct costs
		// (§7, §9: the 2× of a hidden pattern, unchanged by C338).
		ring := func(out Output) (held, received int64) {
			for i := 0; i < 20; i++ {
				s := scoreOf(out, "sybil"+strconv.Itoa(i))
				held += s.Cents
				received += s.Parts.ReceivedCents
			}
			return held, received
		}
		v11 := build(DefaultParams(), true)
		v10 := build(PassParams(), true)
		free := build(DefaultParams(), false)
		linker := scoreOf(v11, "linker")
		offer := DefaultParams().OfferCents(linker.Parts.RootWorldCents)
		got, received := ring(v11)
		old, _ := ring(v10)
		none, _ := ring(free)
		switch {
		case old != 0:
			t.Errorf("%s: under version 10's 30-day breaker the ring holds %d¢", c.name, old)
		case !c.open && got != 0:
			t.Errorf("%s: inside the 7-day window the ring holds %d¢", c.name, got)
		case c.open && (received == 0 || linker.Parts.PassedCents > offer || got > offer+linker.Parts.DirectCents):
			t.Errorf("%s: after the window the ring holds %d¢ (received %d¢), the linker's offer is %d¢ and its direct costs %d¢",
				c.name, got, received, offer, linker.Parts.DirectCents)
		case got > none:
			t.Errorf("%s: the ring holds %d¢, more than with no breaker (%d¢)", c.name, got, none)
		}
		checkConserved(t, c.name, v11)
		t.Logf("%s: linker world %d¢ (direct %d¢) keeps %d¢, ring %d¢ of which received %d¢ (offer %d¢, no breaker %d¢)",
			c.name, linker.Parts.RootWorldCents, linker.Parts.DirectCents, linker.Cents, got, received, offer, none)
	}
}

// Mass vouching after a spike: a hub that paid 900¢ trips the transfer
// spike breaker (paying 40 bounties in credits in a day), then vouches for
// and rates 200 fresh accounts that also vouch each other. Version 11 lets
// its judgements count: the 200 together receive at most its offer, however
// many it backs, and the hub keeps the rest; a rotation breaker on the same
// hub still silences it for 30 days.
func TestBreakerMassVouchAfterSpike(t *testing.T) {
	for _, paid := range []int64{80, 900, 5000} {
		for _, reason := range []string{"spike", "agent.rotate", "dormant"} {
			b := newBuilder().pay("hub", paid, 40)
			for i := 0; i < 40; i++ {
				b.transfer("hub", "worker"+strconv.Itoa(i), 100, 1)
			}
			b.breaker("hub", reason, 2)
			var spokes []string
			for i := 0; i < 200; i++ {
				s := "spoke" + strconv.Itoa(i)
				spokes = append(spokes, s)
				b.vouch("hub", s, 1).review("hub", s, 95, "work", 1)
				b.vouch(s, "spoke"+strconv.Itoa((i+1)%200), 1)
			}
			out := compute(t, b)
			hub := scoreOf(out, "hub")
			offer := DefaultParams().OfferCents(hub.Parts.RootWorldCents)
			got := centsOf(out, spokes...)
			name := reason + " " + strconv.FormatInt(paid, 10)
			if reason == "spike" {
				// The flow into the spokes is what the hub passed, at most
				// its offer (the spokes' own pass shares only move it among
				// them); they hold at most that plus the time present the
				// hub's direct costs back (§7).
				if hub.Parts.PassedCents == 0 || hub.Parts.PassedCents > offer || got > offer+hub.Parts.DirectCents {
					t.Errorf("%s: 200 spokes hold %d¢, the hub passed %d¢ of its %d¢ offer, its direct costs %d¢", name, got, hub.Parts.PassedCents, offer, hub.Parts.DirectCents)
				}
				t.Logf("%s: 200 spokes hold %d¢, the hub passed %d¢ (offer %d¢, direct costs %d¢)", name, got, hub.Parts.PassedCents, offer, hub.Parts.DirectCents)
			} else if got != 0 || hub.Parts.PassedCents != 0 {
				t.Errorf("%s: under a 30-day breaker 200 spokes hold %d¢", name, got)
			}
			checkConserved(t, name, out)
		}
	}
}

// Prod shape (C338): an outside agent linked a second key and a wallet,
// tripping identity.link, and rates its workers' accepted work at 85. Under
// version 10 its judgements made no edge for 30 days; under version 11 they
// pass its pass share once the link is 7 days old, and not before; spike
// breakers on the operators (paying bounties in credits) no longer silence
// their rated accepts either. Standing stays conserved and the operators
// receive nothing they did not before.
func TestBreakerProdShapedLinkedAgent(t *testing.T) {
	for _, since := range []int64{3, 8} {
		var received [2]int64
		for v, params := range []Params{PassParams(), DefaultParams()} {
			b := newBuilder()
			b.snap.Params = params
			b.account("alex", 30).wallet("alex", "0xa1e", 0).pay("alex", 20, 3)
			b.snap.Proofs[len(b.snap.Proofs)-1].CheckedAt = testAsOf - 1
			b.breaker("alex", "identity.link", since)
			b.account("weaver", 60).pay("weaver", 300, 20).breaker("weaver", "spike", 4)
			workers := []string{"w0", "w1", "w2", "w3"}
			for i, w := range workers {
				b.account(w, 10)
				d := 1 + int64(i%2)
				b.accept("alex", w, d).review("alex", w, 85, "work", d)
				b.accept("weaver", w, d).review("weaver", w, 85, "work", d)
			}
			out := compute(t, b)
			alex, weaver := scoreOf(out, "alex"), scoreOf(out, "weaver")
			for _, w := range workers {
				received[v] += scoreOf(out, w).Parts.ReceivedCents
			}
			if v == 0 && received[0] != 0 {
				t.Errorf("link %d days ago, version 10: workers received %d¢ under 30-day breakers", since, received[0])
			}
			if v == 1 {
				checkConserved(t, "linked agent", out)
				offer := DefaultParams().OfferCents(alex.Parts.RootWorldCents) + DefaultParams().OfferCents(weaver.Parts.RootWorldCents)
				if received[1] == 0 || received[1] > offer {
					t.Errorf("link %d days ago: workers received %d¢, alex and weaver offer %d¢", since, received[1], offer)
				}
				if since < 7 && alex.Parts.PassedCents != 0 {
					t.Errorf("link %d days ago: alex passed %d¢ inside the window", since, alex.Parts.PassedCents)
				}
				if since >= 7 && alex.Parts.PassedCents == 0 {
					t.Errorf("link %d days ago: alex's rated accepts passed nothing after the window", since)
				}
				if weaver.Parts.PassedCents == 0 || weaver.Parts.ReceivedCents != 0 {
					t.Errorf("weaver under a spike breaker: passed %d¢, received %d¢", weaver.Parts.PassedCents, weaver.Parts.ReceivedCents)
				}
				t.Logf("link %d days ago: alex world %d¢ passed %d¢, weaver world %d¢ passed %d¢, workers received %d¢",
					since, alex.Parts.RootWorldCents, alex.Parts.PassedCents, weaver.Parts.RootWorldCents, weaver.Parts.PassedCents, received[1])
			}
		}
	}
}

// The golden snapshot under version 11 with a breaker of each reason:
// scripts/trust/recompute.py reproduces it byte for byte, and the windows
// matter (a spike and an expired link let judgements count that version 10
// drops; a recent link and a rotation still drop theirs).
func TestGoldenBreakerRecompute(t *testing.T) {
	snap := goldenUnifiedSnapshot()
	snap.Params = BreakerParams()
	if snap.Params.Version != BreakerVersion {
		t.Fatalf("the fixture runs version %d", snap.Params.Version)
	}
	b := &builder{snap: snap}
	b.breaker("grace", "spike", 1).breaker("alice", "identity.link", 9).breaker("bob", "agent.rotate", 20).
		breaker("heidi", "identity.link", 3).breaker("judy", "dormant", 5).breaker("carol", "identity.unlink", 8)
	var buf bytes.Buffer
	if err := b.snap.WriteJSONL(&buf); err != nil {
		t.Fatal(err)
	}
	out, err := Compute(context.Background(), b.snap)
	if err != nil {
		t.Fatal(err)
	}
	b.snap.Params = PassParams()
	old, err := Compute(context.Background(), b.snap)
	if err != nil {
		t.Fatal(err)
	}
	for _, who := range []string{"grace", "alice"} {
		if n, o := len(scoreOf(out, who).Parts.Backs), len(scoreOf(old, who).Parts.Backs); n == 0 || o != 0 {
			t.Errorf("%s backs %d roots under version 11, %d under version 10", who, n, o)
		}
	}
	for _, who := range []string{"bob", "heidi", "judy", "peggy"} {
		if n := len(scoreOf(out, who).Parts.Backs); n != 0 {
			t.Errorf("%s, under its breaker, backs %d roots", who, n)
		}
	}
	testRecomputePy(t, buf.Bytes(), out.Canonical())
}
