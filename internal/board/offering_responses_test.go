package board

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"swarmmemo/internal/services/servicestest"
)

// C542: a new paid call reaches its seller (inbox entry with the amount,
// claim_by and next; a webhook without kinds; on:"received" wake-ups), and
// the listings leave out a provider that lets calls lapse unanswered,
// ranking the ones that respond first.

func TestOfferingCallAlertReachesTheSeller(t *testing.T) {
	c := updatesConfig()
	c.Features = Features{Services: []string{"wakeup"}, InboxEntries: InboxRead}
	c.Offerings = topupConfig(t, &fakeFacilitator{}, "")
	s := openTest(t, c)
	s.UseServiceMeter(servicestest.NewMeter(1<<30), &servicestest.Params{})
	t.Cleanup(s.stopServices)
	key := keyFor(181)
	provider(t, s, key, "alert-seller")
	publish(t, s, key, listing("oracle", nil))
	account := accountOf(t, s, key)
	run(t, s, svcCall(key, "wakeup", "schedule", map[string]any{"key": "calls", "on": "received"}, 1, "wake-alert"))
	// A subscription that named no kinds: the default set takes offering_call.
	if _, err := s.db.Exec("INSERT INTO webhook_subscriptions(id,account,created_by,url,secret,state,created_at,confirmed_at) VALUES('wh_alert',?,?,'https://hooks.example.org/a','s','active',1,1)", account, keyID(key)); err != nil {
		t.Fatal(err)
	}
	accepted := offeringQuoteFor(t, s, buyCmd("alert-seller/oracle", question, ""))
	id := callOf(t, run(t, s, buyCmd("alert-seller/oracle", question, pay(t, accepted, 90, nil))))["call"].(string)
	var body string
	if err := s.db.QueryRow("SELECT body FROM webhook_deliveries WHERE subscription='wh_alert'").Scan(&body); err != nil {
		t.Fatalf("no delivery to a default subscription: %v", err)
	}
	var got struct {
		Reason string `json:"reason"`
		Read   string `json:"read"`
		Entry  struct {
			Kind    string         `json:"kind"`
			Subject string         `json:"subject"`
			Detail  map[string]any `json:"detail"`
		} `json:"entry"`
	}
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatal(err)
	}
	d := got.Entry.Detail
	if got.Reason != inboxOfferingCall || got.Entry.Kind != inboxOfferingCall || got.Entry.Subject != id || d["amount"] != "5" || d["claim_by"] == nil ||
		d["next"] != OfferingCallNext || d["offering"] != "oracle" || !strings.Contains(got.Read, "offering.claim") || strings.Contains(body, "Lisbon") {
		t.Fatalf("delivery %s", body)
	}
	upd := run(t, s, signed(key, Command{Operation: "updates.get", Target: keyID(key)}))
	entries, _ := json.Marshal(upd.Data["entries"])
	if !strings.Contains(string(entries), `"next":"`+OfferingCallNext+`"`) || !strings.Contains(string(entries), `"claim_by":`) {
		t.Fatalf("entries %s", entries)
	}
	if n := sqlCount(t, s, "SELECT count(*) FROM wakeup_notices WHERE account=? AND kind='received'", account); n != 1 {
		t.Fatalf("%d on:received notices", n)
	}
}

// seedCall inserts a call of account's offering: state, its payer, when it
// arrived, its claim_by, and its claim or close time.
func seedCall(t *testing.T, s *Store, account, state, payer string, created, claimBy, claimed, closed int64) {
	t.Helper()
	id := fmt.Sprintf("oc_%032x", time.Now().UnixNano())
	if _, err := s.db.Exec(`INSERT INTO offering_calls(id,account,name,rev,payer,amount,network,asset,pay_to,input,input_sha256,auth_nonce,quote_hash,valid_before,state,poll_hash,created_at,claim_by,claimed_at,closed_at)
VALUES(?,?,'oracle',1,?,5000000,'eip155:8453',?,?,'{}','x',?,'q',1,?,'p',?,?,?,?)`, id, account, payer, topupUSDC, offeringWallet, id, state, created, claimBy, claimed, closed); err != nil {
		t.Fatal(err)
	}
}

func listedNames(t *testing.T, s *Store) []string {
	t.Helper()
	var out []string
	for _, o := range run(t, s, Command{Operation: "offering.list"}).Data["offerings"].([]map[string]any) {
		out = append(out, o["provider"].(map[string]any)["handle"].(string))
	}
	return out
}

func TestOfferingListingDropsQuietProviders(t *testing.T) {
	s := offeringStore(t, &fakeFacilitator{})
	now := int64(testTime)
	day := int64(86400)
	keys := map[string]ed25519.PrivateKey{}
	accounts := map[string]string{}
	for i, h := range []string{"quiet-one", "fresh-one", "late-one", "back-one", "self-one"} {
		keys[h] = keyFor(byte(190 + i))
		provider(t, s, keys[h], h)
		publish(t, s, keys[h], listing("oracle", nil))
		accounts[h] = accountOf(t, s, keys[h])
	}
	// quiet-one: a call lapsed yesterday, nothing answered.
	seedCall(t, s, accounts["quiet-one"], "lapsed", topupPayer, now-day-900, now-day, 0, now-day)
	// late-one: claimed 10 days ago, then a lapse 5 days ago: quiet.
	seedCall(t, s, accounts["late-one"], "answered", topupPayer, now-10*day-60, now-10*day+900, now-10*day, 0)
	seedCall(t, s, accounts["late-one"], "lapsed", topupPayer, now-5*day-900, now-5*day, 0, now-5*day)
	// back-one: a lapse 10 days ago, then a claim 9 days ago: listed.
	seedCall(t, s, accounts["back-one"], "lapsed", topupPayer, now-10*day-900, now-10*day, 0, now-10*day)
	seedCall(t, s, accounts["back-one"], "paid", topupPayer, now-9*day-60, now-9*day+900, now-9*day, 0)
	// self-one: a lapse, and a claim of a call it paid itself: still quiet.
	seedCall(t, s, accounts["self-one"], "lapsed", topupPayer, now-2*day-900, now-2*day, 0, now-2*day)
	seedCall(t, s, accounts["self-one"], "paid", offeringWallet, now-day-60, now-day+900, now-day, 0)

	// fresh-one (no calls) and back-one are listed; back-one responded, so first.
	if got := listedNames(t, s); fmt.Sprint(got) != "[back-one fresh-one]" {
		t.Fatalf("listed %v", got)
	}
	dir, err := s.OfferingsDirectory(testContext, 0)
	if err != nil || len(dir) != 2 || dir[0].Provider != "back-one" {
		t.Fatalf("directory %+v %v", dir, err)
	}
	// Still readable by id, marked.
	o := run(t, s, Command{Operation: "offering.get", Target: "quiet-one/oracle"}).Data["offering"].(map[string]any)
	r := o["responses"].(map[string]any)
	if o["listed"] != false || !strings.Contains(fmt.Sprint(o["unlisted"]), "lapse") || r["lapsed"] != int64(1) || r["responded"] != int64(0) || r["rate"] != 0.0 || r["last_responded_at"] != nil {
		t.Fatalf("quiet offering %v %v", o["listed"], r)
	}
	if o := run(t, s, Command{Operation: "offering.get", Target: "fresh-one/oracle"}).Data["offering"].(map[string]any); o["listed"] != true || o["unlisted"] != nil || o["responses"].(map[string]any)["rate"] != nil {
		t.Fatalf("fresh offering %v", o)
	}
	// A decline is a response: quiet-one is listed again, ranked first.
	seedCall(t, s, accounts["quiet-one"], "declined", topupPayer, now-3600, now+600, 0, now-60)
	if got := listedNames(t, s); fmt.Sprint(got) != "[quiet-one back-one fresh-one]" {
		t.Fatalf("listed after a decline %v", got)
	}
	r = run(t, s, Command{Operation: "offering.get", Target: "quiet-one/oracle"}).Data["offering"].(map[string]any)["responses"].(map[string]any)
	if r["responded"] != int64(1) || r["lapsed"] != int64(1) || r["rate"] != 0.5 || r["last_responded_at"] != now-60 {
		t.Fatalf("responses %v", r)
	}
	// The lapse ages out of the record window: late-one is listed again.
	s.now = func() time.Time { return time.Unix(now+26*day, 0) }
	if got := listedNames(t, s); !strings.Contains(fmt.Sprint(got), "late-one") || strings.Contains(fmt.Sprint(got), "self-one") {
		t.Fatalf("listed later %v", got)
	}
	caps := s.OfferingsCapabilities()["listing"].(map[string]any)
	if caps["respond_days"] != OfferingRespondDays || caps["rule"] != OfferingListedRule {
		t.Fatalf("capabilities %v", caps)
	}
}
