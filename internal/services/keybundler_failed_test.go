package services

import (
	"encoding/json"
	"strings"
	"testing"
)

// C548 (Skitter round 5, evidencebridgeai 6e9324ba; vm2 round 6): a tools
// call whose seller could not be paid ("no applicable payers found") was
// charged 5,600 credits for delivered 0, its answer showed the upstream's
// receipt as network tempo with tx_hash "", and nothing said how 5,600
// followed from the 5,000 the bundler billed. Now an answer that delivered
// nothing costs only the call's base, the upstream receipt without a
// transaction names no network (settlement none), our own payment block
// says settlement internal, and every answer breaks its cost down.
func TestBundlerPaymentFailedNotCharged(t *testing.T) {
	h, api := newBundlerHarness(t, "", "")
	if _, err := h.bundlerRead(testSubject, "tools_search", `{"query":"weather"}`); err != nil {
		t.Fatal(err)
	}
	quote := creditsFor(bundlerCost(2000))
	failed := `{"result":{"calls":[{"id":"` + toolOK + `","body":{"error":"no applicable payers found"},"charged_usd":0.005,"delivered":false,"outcome":"payment_failed"}],"delivered":0,"requested":1},` +
		`"receipts":[{"tool":"` + toolOK + `","amount":"0","delivered":false,"network":"tempo","tx_hash":""}],"billing":{"charged_credits":5}}`
	api.invokeBody = failed
	before := h.charged()
	out, err := h.call(testSubject, `{"resource":"tool:`+toolOK+`","body":{}}`, quote)
	if err != nil {
		t.Fatal(err)
	}
	if got := h.charged() - before; got != creditsFor(0) {
		t.Fatalf("charged %d for a payment_failed call, want only the base %d", got, creditsFor(0))
	}
	r := resultOf(out)
	raw, _ := json.Marshal(r)
	if !strings.Contains(string(raw), "delivered nothing (outcome payment_failed)") || r["payment"] != nil {
		t.Fatalf("result %s: want the not_charged note and no payment", raw)
	}
	if c, _ := r["charge"].(map[string]any); c == nil || c["credits"] != float64(creditsFor(0)) || c["tool"] != 0.0 || c["base"] != float64(creditsFor(0)) || c["paid_usd"] != "0" {
		t.Fatalf("charge %v", r["charge"])
	}
	var body struct {
		Receipts []map[string]any `json:"receipts"`
	}
	b, _ := json.Marshal(r["body"])
	if err = json.Unmarshal(b, &body); err != nil || len(body.Receipts) != 1 {
		t.Fatalf("body %s: %v", b, err)
	}
	rc := body.Receipts[0]
	up, _ := rc["upstream"].(map[string]any)
	if rc["network"] != nil || rc["tx_hash"] != nil || up == nil || up["network"] != nil || up["settlement"] != "none" || up["note"] != BundlerUpstreamNote {
		t.Fatalf("upstream receipt %v", rc)
	}
	// Our spend still counts against the caps: the bundler billed 5 credits.
	var state string
	var amount int64
	if err = h.db.QueryRow("SELECT state, amount FROM x402_payments ORDER BY rowid DESC LIMIT 1").Scan(&state, &amount); err != nil || state == "failed" || amount != 5000 {
		t.Fatalf("payment row %s %d %v", state, amount, err)
	}

	// payment_refused too; a delivered call keeps its charge and explains it.
	api.invokeBody = strings.Replace(failed, "payment_failed", "payment_refused", 1)
	before = h.charged()
	if _, err = h.call(testSubject, `{"resource":"tool:`+toolOK+`","body":{"n":1}}`, quote); err != nil || h.charged()-before != creditsFor(0) {
		t.Fatalf("payment_refused: charged %d, %v", h.charged()-before, err)
	}
	for i, body := range []string{
		strings.Replace(failed, `"delivered":false,"outcome"`, `"delivered":true,"outcome"`, 1), // contrary
		strings.Replace(failed, `"outcome":"payment_failed"`, `"outcome":"delivered"`, 1),
	} {
		api.invokeBody = strings.Replace(body, `"delivered":0,`, `"delivered":1,`, 1)
		before = h.charged()
		out, err = h.call(testSubject, `{"resource":"tool:`+toolOK+`","body":{"d":`+string(rune('0'+i))+`}}`, quote)
		if err != nil {
			t.Fatal(err)
		}
		if got := h.charged() - before; got != creditsFor(5000) {
			t.Fatalf("delivered body %d: charged %d, want %d", i, got, creditsFor(5000))
		}
		r = resultOf(out)
		p, _ := r["payment"].(map[string]any)
		c, _ := r["charge"].(map[string]any)
		if p == nil || p["amount"] != "5000" || p["settlement"] != "internal" || p["network"] != nil ||
			c == nil || c["credits"] != float64(creditsFor(5000)) || c["base"] != 100.0 || c["tool"] != float64(creditsFor(5000)-100) || c["paid_usd"] != "0.005" || c["note"] != X402ChargeNote {
			t.Fatalf("delivered body %d: payment %v charge %v", i, p, c)
		}
	}
}

// bundlerNothingDelivered reads the upstream's labels strictly.
func TestBundlerNothingDelivered(t *testing.T) {
	for body, want := range map[string]bool{
		`{"result":{"calls":[{"outcome":"payment_failed","delivered":false}],"delivered":0}}`:                        true,
		`{"result":{"calls":[{"outcome":"payment_failed"}]}}`:                                                        true,
		`{"result":{"calls":[{"outcome":"payment_failed","delivered":true}]}}`:                                       false,
		`{"result":{"calls":[{"outcome":"payment_failed"},{"outcome":"delivered","delivered":true}],"delivered":1}}`: false,
		`{"result":{"calls":[{"delivered":false},{"delivered":false}],"delivered":0}}`:                               true,
		`{"result":{"calls":[{"delivered":false}],"delivered":"0"}}`:                                                 false,
		`{"result":{"calls":[{"delivered":false}]}}`:                                                                 false,
		`{"result":{"calls":[],"delivered":0}}`:                                                                      false,
		`{"result":{"calls":[{"outcome":"delivered_empty","delivered":true}],"delivered":1}}`:                        true,
		`{"result":{"calls":[{"outcome":"PAYMENT_FAILED","delivered":false}],"delivered":1}}`:                        false,
		`{"results":[{"delivered":false}]}`:                                                                          false,
	} {
		var out map[string]json.RawMessage
		if err := json.Unmarshal([]byte(body), &out); err != nil {
			t.Fatal(err)
		}
		if _, got := bundlerNothingDelivered(out); got != want {
			t.Errorf("%s: %v, want %v", body, got, want)
		}
	}
}
