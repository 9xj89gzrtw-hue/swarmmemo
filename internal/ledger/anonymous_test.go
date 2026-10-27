package ledger

import (
	"database/sql"
	"fmt"
	"testing"

	"swarmmemo/internal/allowance"
)

// Credit for callers without a key: anonymous subjects get the floor, and
// together a small share of the credit budget. That share is the hard bound
// on what every anonymous subject together can spend in a day, whatever
// spills from the standing slice and however many networks call; the
// signed-services lever takes it to zero at once. Signed callers and other
// resources are untouched.

// anonCreditParams: credit budget 10,000, a floor of 20 a claimant (the
// floor slice, 2,500, holds 125 of them), anonymous share 10% of the budget
// (1,000).
func anonCreditParams() AllowanceParams {
	p := DefaultAllowanceParams()
	rp := p.Resources[allowance.Credit]
	rp.Budget, rp.SpendCeiling, rp.InboundCap = 10000, 10000, 10000
	rp.Floor, rp.Cap, rp.AnonymousSharePPM = 20, 4000, 100_000
	return p
}

func (h *harness) spendCredit(s allowance.Subject, units int64) error {
	return h.do(func(q *sql.Tx) error {
		_, err := h.l.Spend(ctx, q, s, allowance.Credit, units, Ref{Service: "notary", Op: "service.call", Method: "stamp"}, h.now)
		return err
	})
}

func (h *harness) creditDay() dayState {
	h.t.Helper()
	d, ok, err := loadDay(ctx, h.db, allowance.Credit, h.now/86400)
	if err != nil || !ok {
		h.t.Fatalf("credit day: %v %v", ok, err)
	}
	return d
}

func refusalCode(err error) string {
	if e, ok := err.(*allowance.Err); ok {
		return e.Code
	}
	return fmt.Sprint(err)
}

func TestAnonymousCreditPerNetworkAndShareCap(t *testing.T) {
	h := newHarness(t, anonCreditParams())
	// 05:00 UTC: 9/24 of the anonymous day is released (anonReleased), room
	// for the first eighteen networks; the rest is released by 20:00.
	h.now += 5 * 3600
	// One network gets its cap, and no more.
	a := anonSubject("net-a")
	if err := h.spendCredit(a, 20); err != nil {
		t.Fatal(err)
	}
	if err := h.spendCredit(a, 1); refusalCode(err) != "quota_exhausted" {
		t.Fatalf("a network past its share: %v", err)
	}
	// Networks together stop at the 10% share (1,000), even when the
	// standing slice's unused water may spill to them.
	spent := int64(20)
	var last error
	for i := 0; i < 200; i++ {
		if i == 10 {
			h.now += 18 * 3600 // spill boundaries pass: the standing slice lends
		}
		if last = h.spendCredit(anonSubject(fmt.Sprintf("net-%d", i)), 20); last != nil {
			break
		}
		spent += 20
	}
	if refusalCode(last) != "global_quota_exhausted" || spent != 1000 {
		t.Fatalf("anonymous callers spent %d, last %v; want 1000 then global_quota_exhausted", spent, last)
	}
	d := h.creditDay()
	if room, _ := anonRoom(&d, h.p.Resources[allowance.Credit], noLevers(), h.now); lendable(&d, h.p.Resources[allowance.Credit], sliceStanding, h.now) == 0 || room != 0 {
		t.Fatalf("spill may run, but the anonymous share is spent: room %d, %+v", room, d.Slices)
	}
	if d.Anon.Claimed != 1000 {
		t.Fatalf("anonymous lots drew %d, want exactly their share", d.Anon.Claimed)
	}
	// Signed callers still draw their own water.
	if err := h.spendCredit(signedSubject("signed-1"), 16); err != nil {
		t.Fatalf("signed spend after the anonymous share ran dry: %v", err)
	}
	// Posting bytes for the same networks are untouched by the credit cap.
	if err := h.spend(anonSubject("net-a"), 50); err != nil {
		t.Fatalf("anonymous posting: %v", err)
	}
}

func TestAnonymousCreditLeverOff(t *testing.T) {
	h := newHarness(t, anonCreditParams())
	a := anonSubject("net-a")
	if err := h.spendCredit(a, 5); err != nil {
		t.Fatal(err)
	}
	// Pulled mid-day: the network's unspent share stops at once (anonymous
	// lots have no room left), a new network gets nothing, and signed credit
	// and anonymous posting go on.
	h.levers.lv.SignedServices = true
	if err := h.spendCredit(a, 1); refusalCode(err) != "global_quota_exhausted" {
		t.Fatalf("an issued share after signed-services: %v", err)
	}
	if err := h.spendCredit(anonSubject("net-b"), 1); refusalCode(err) != "quota_exhausted" {
		t.Fatalf("a new network under signed-services: %v", err)
	}
	b, err := h.l.Balance(ctx, h.db, anonSubject("net-c"), allowance.Credit, h.now)
	if err != nil || b.Entitlement != 0 {
		t.Fatalf("prospective anonymous credit under signed-services: %+v %v", b, err)
	}
	if err := h.spendCredit(signedSubject("signed-1"), 10); err != nil {
		t.Fatalf("signed credit under signed-services: %v", err)
	}
	if err := h.spend(anonSubject("net-b"), 10); err != nil {
		t.Fatalf("anonymous posting under signed-services: %v", err)
	}
	// Released: anonymous callers draw again, within the same share.
	h.levers.lv.SignedServices = false
	if err := h.spendCredit(anonSubject("net-d"), 20); err != nil {
		t.Fatalf("after release: %v", err)
	}
}

// With the anonymous share at 100% (post_bytes' default) the cap on
// anonymous draws never binds: posting is unchanged by it.
func TestAnonymousShareCapInertAtFullShare(t *testing.T) {
	h := newHarness(t, smallParams())
	for i := 0; i < 5; i++ {
		if err := h.spend(anonSubject(fmt.Sprintf("n%d", i)), 100); err != nil {
			t.Fatalf("anonymous post %d: %v", i, err)
		}
	}
	d, _, _ := loadDay(ctx, h.db, allowance.PostBytes, h.now/86400)
	if room, hourly := anonRoom(&d, h.p.Resources[allowance.PostBytes], noLevers(), h.now); room < d.BudgetEffective-d.Anon.Claimed || hourly {
		t.Fatalf("at a full share the cap must not bind: room %d, drawn %d", room, d.Anon.Claimed)
	}
}

// Security review 1.21, M3: where the anonymous share is capped below the
// whole budget (credit), its day is released over the day (a sixth at
// midnight, a 24th each hour), so one burst early in the day cannot take the
// whole day's share; what an hour
// leaves unused carries forward, and the refusal says when more comes.
func TestSecReview121AnonymousShareReleasedHourly(t *testing.T) {
	h := newHarness(t, anonCreditParams()) // anonymous: 1,000 a day, 20 a network
	h.now += 30 * 60                       // 00:30 UTC: a sixth released (166)
	burst := func() (int64, error) {
		var spent int64
		for i := 0; i < 60; i++ {
			if err := h.spendCredit(anonSubject(fmt.Sprintf("burst-%d-%d", h.now, i)), 20); err != nil {
				return spent, err
			}
			spent += 20
		}
		return spent, nil
	}
	spent, err := burst()
	if spent != 160 || refusalCode(err) != "global_quota_exhausted" {
		t.Fatalf("first hour: spent %d, %v; want 160 then global_quota_exhausted", spent, err)
	}
	if e, ok := err.(*allowance.Err); !ok || e.RetryAfter <= 0 || e.RetryAfter > 1800 || e.NextOpenAt != allowance.NextHour(h.now) || e.NextOpenAt-h.now != int64(e.RetryAfter) {
		t.Fatalf("the refusal waits for the next hour, not midnight: %+v", err)
	}
	// 10:30: 14/24 released (583) less the 160 drawn: the unused hours carry
	// forward.
	h.now += 10 * 3600
	if spent, err = burst(); spent != 420 || refusalCode(err) != "global_quota_exhausted" {
		t.Fatalf("after ten hours: spent %d, %v; want 420", spent, err)
	}
	// 23:30: the whole day is released; anonymous callers still stop at their share.
	h.now += 13 * 3600
	if spent, err = burst(); spent != 420 || refusalCode(err) != "global_quota_exhausted" {
		t.Fatalf("last hour: spent %d, %v; want the rest of 1,000", spent, err)
	}
	if e, ok := err.(*allowance.Err); !ok || int64(e.RetryAfter) != 86400-h.now%86400 || e.NextOpenAt != allowance.NextDay(h.now) {
		t.Fatalf("with the whole day released the refusal waits for midnight: %+v", err)
	}
	// Posting (a full anonymous share) is not held back.
	if err := h.spend(anonSubject("poster"), 50); err != nil {
		t.Fatalf("anonymous posting: %v", err)
	}
}
