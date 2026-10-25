package services

// C578: an answer longer than the call's limit is returned cut and charged,
// never discarded after we paid for it.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// rowsJSON is a JSON object with a rows array of n small objects.
func rowsJSON(n int) string {
	rows := make([]string, n)
	for i := range rows {
		rows[i] = fmt.Sprintf(`{"i":%d,"strike":%d.5,"bid":1.25,"ask":1.3}`, i, 100+i)
	}
	return `{"symbol":"TSLA","rows":[` + strings.Join(rows, ",") + `]}`
}

func hexSHA(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func TestX402OversizedJSONIsCutWhereItParses(t *testing.T) {
	full := rowsJSON(200) // about 9 KiB; "search" allows 1,024 bytes
	h := newX402Harness(t, &fakeX402{price: 1000, paidBody: full}, `{}`)
	out, err := h.call(testSubject, `{"resource":"search"}`, creditsFor(20000))
	if err != nil {
		t.Fatal(err)
	}
	r := resultOf(out)
	raw, _ := json.Marshal(r["body"])
	var body struct {
		Symbol string            `json:"symbol"`
		Rows   []json.RawMessage `json:"rows"`
	}
	if r["encoding"] != "json" || r["truncated"] != true || json.Unmarshal(raw, &body) != nil || body.Symbol != "TSLA" || len(body.Rows) < 10 || len(body.Rows) >= 200 {
		t.Fatalf("cut JSON: %v", r)
	}
	if n := r["bytes"].(float64); n > 1024 || n < 512 || int(n) != len(raw) {
		t.Fatalf("bytes %v for %d bytes of body", n, len(raw))
	}
	if r["full_bytes"] != float64(len(full)) || r["sha256"] != hexSHA(full) || !strings.Contains(r["truncation_note"].(string), "still parses") {
		t.Fatalf("flags: %v", r)
	}
	if p, _ := r["payment"].(map[string]any); p["truncated"] != true {
		t.Fatalf("the receipt does not record the cut: %v", p)
	}
	// Charged what was paid, as for a whole answer; the row is a plain paid
	// one (no discard), with the whole answer's size.
	if got := h.charged(); got != creditsFor(1000) {
		t.Fatalf("charged %d, want %d", got, creditsFor(1000))
	}
	var state, reason string
	var n int
	if err := h.db.QueryRow("SELECT state, reason, response_bytes FROM x402_payments").Scan(&state, &reason, &n); err != nil || state != "paid" || reason != "" || n != len(full) {
		t.Fatalf("payment row %s %q %d %v", state, reason, n, err)
	}
}

func TestX402OversizedTextIsItsPrefix(t *testing.T) {
	full := strings.Repeat("é line of text\n", 300)
	h := newX402Harness(t, &fakeX402{price: 1000, paidBody: full, paidType: "text/plain; charset=utf-8"}, `{}`)
	out, err := h.call(testSubject, `{"resource":"search"}`, creditsFor(20000))
	if err != nil {
		t.Fatal(err)
	}
	r := resultOf(out)
	body, _ := r["body"].(string)
	if r["encoding"] != "text" || r["truncated"] != true || !strings.HasPrefix(full, body) || len(body) < 1021 || len(body) > 1024 || r["bytes"] != float64(len(body)) {
		t.Fatalf("cut text: %d bytes, %v", len(body), r["encoding"])
	}
	if r["full_bytes"] != float64(len(full)) || r["sha256"] != hexSHA(full) || r["text_is_untrusted"] != true || h.charged() != creditsFor(1000) {
		t.Fatalf("flags: %v, charged %d", r, h.charged())
	}
}

func TestX402AnswerAtTheLimitIsWhole(t *testing.T) {
	full := `{"x":"` + strings.Repeat("y", 1024-8) + `"}`
	if len(full) != 1024 {
		t.Fatalf("fixture %d bytes", len(full))
	}
	h := newX402Harness(t, &fakeX402{price: 1000, paidBody: full}, `{}`)
	out, err := h.call(testSubject, `{"resource":"search"}`, creditsFor(20000))
	if err != nil {
		t.Fatal(err)
	}
	r := resultOf(out)
	raw, _ := json.Marshal(r["body"])
	if r["encoding"] != "json" || string(raw) != full || r["bytes"] != 1024.0 {
		t.Fatalf("at the limit: %v", r)
	}
	for _, k := range []string{"truncated", "full_bytes", "sha256", "truncation_note"} {
		if _, ok := r[k]; ok {
			t.Fatalf("a whole answer has %s: %v", k, r)
		}
	}
	if p, _ := r["payment"].(map[string]any); p["truncated"] != nil || h.charged() != creditsFor(1000) {
		t.Fatalf("receipt %v, charged %d", p, h.charged())
	}
}

func TestX402EndlessAnswerStopsAtTheCeiling(t *testing.T) {
	h := newX402Harness(t, &fakeX402{price: 1000, endless: true}, `{}`)
	out, err := h.call(testSubject, `{"resource":"search","max_bytes":65536}`, creditsFor(20000)+x402ExtraCredits(X402ResponseBytesCeiling))
	if err != nil {
		t.Fatal(err)
	}
	r := resultOf(out)
	body, _ := r["body"].(string)
	if r["encoding"] != "text" || r["truncated"] != true || len(body) != X402ResponseBytesCeiling || r["full_bytes_over"] != float64(X402ResponseBytesCeiling) {
		t.Fatalf("endless: %d bytes, %v %v %v", len(body), r["encoding"], r["truncated"], r["full_bytes_over"])
	}
	if _, ok := r["sha256"]; ok {
		t.Fatal("a hash of an answer never read whole")
	}
	if got, want := h.charged(), creditsFor(1000)+x402ExtraCredits(X402ResponseBytesCeiling); got != want {
		t.Fatalf("charged %d, want %d", got, want)
	}
}

func TestX402MaxBytesRaisesTheLimitAndThePrice(t *testing.T) {
	full := strings.Repeat("0123456789abcdef", 2048) // 32 KiB of text
	h := newX402Harness(t, &fakeX402{price: 1000, paidBody: full, paidType: "text/plain"}, `{}`)
	args := `{"resource":"search","max_bytes":20000}`
	extra := x402ExtraCredits(20000) // 8 KiB started over 12 KiB
	if extra != 8 {
		t.Fatalf("extra %d", extra)
	}
	// The quote covers the bytes: a max_cost without them is refused before
	// anything is paid.
	if _, err := h.call(testSubject, args, creditsFor(20000)); err == nil || h.fake.paid != 0 {
		t.Fatalf("max_cost without the bytes: %v, paid %d", err, h.fake.paid)
	}
	out, err := h.call(testSubject, args, creditsFor(20000)+extra)
	if err != nil {
		t.Fatal(err)
	}
	r := resultOf(out)
	body, _ := r["body"].(string)
	c, _ := r["charge"].(map[string]any)
	if len(body) != 20000 || r["truncated"] != true || c["bytes"] != float64(extra) || c["credits"] != float64(creditsFor(1000)+extra) {
		t.Fatalf("max_bytes 20000: %d bytes, charge %v", len(body), c)
	}
	if got := h.charged(); got != creditsFor(1000)+extra {
		t.Fatalf("charged %d", got)
	}
	// Within the default, no bytes part even with a large max_bytes.
	h.fake.paidBody = rowsJSON(3)
	before := h.charged()
	out, err = h.call(testSubject, args, creditsFor(20000)+extra)
	if err != nil {
		t.Fatal(err)
	}
	if c, _ := resultOf(out)["charge"].(map[string]any); c["bytes"] != nil || h.charged()-before != creditsFor(1000) {
		t.Fatalf("small answer: %v", c)
	}
	for _, bad := range []string{`0`, `65537`, `"20000"`} {
		if _, err := h.call(testSubject, `{"resource":"search","max_bytes":`+bad+`}`, creditsFor(20000)+100); err == nil {
			t.Fatalf("max_bytes %s accepted", bad)
		}
	}
}

// A bundler tool's answer longer than the limit is cut after the envelope
// is scrubbed: billing stays ours, and the tool keeps its charge.
func TestBundlerOversizedAnswerIsCut(t *testing.T) {
	h, api := newBundlerHarness(t, "", "")
	if _, err := h.bundlerRead(testSubject, "tools_search", `{"query":"weather"}`); err != nil {
		t.Fatal(err)
	}
	rows := make([]string, 600)
	for i := range rows {
		rows[i] = fmt.Sprintf(`{"strike":%d,"bid":1.25,"ask":1.3,"iv":0.51}`, 100+i)
	}
	api.invokeBody = `{"results":[{"id":"` + toolOK + `","delivered":true,"response":{"options":[` + strings.Join(rows, ",") + `]}}],"billing":{"charged_credits":2.8,"balance_credits":2997}}`
	quote := creditsFor(bundlerCost(2000))
	out, err := h.call(testSubject, `{"resource":"tool:`+toolOK+`","body":{"symbol":"TSLA"}}`, quote)
	if err != nil {
		t.Fatal(err)
	}
	r := resultOf(out)
	raw, _ := json.Marshal(r["body"])
	var body struct {
		Results []struct {
			Response struct {
				Options []json.RawMessage `json:"options"`
			} `json:"response"`
		} `json:"results"`
	}
	if r["encoding"] != "json" || r["truncated"] != true || json.Unmarshal(raw, &body) != nil || len(body.Results) != 1 || len(body.Results[0].Response.Options) < 100 {
		t.Fatalf("cut tool answer: %v %v %d", r["encoding"], r["truncated"], len(raw))
	}
	if len(raw) > X402ResponseBytesMax || bytes.Contains(raw, []byte("balance")) || r["full_bytes"].(float64) <= X402ResponseBytesMax {
		t.Fatalf("cut tool answer: %d bytes, full %v", len(raw), r["full_bytes"])
	}
	if got := h.charged(); got != creditsFor(2800) {
		t.Fatalf("charged %d, want the billed %d", got, creditsFor(2800))
	}
}

// At the ceiling, every encoding still fits the stored call record.
func TestX402CeilingFitsTheStoredBody(t *testing.T) {
	cfg := testX402Config(t, `{}`, testResources)
	x := &x402{cfg: cfg, byID: map[string]*X402Resource{}}
	res := cfg.Resources[0]
	p := x402Plan{res: &res, limit: X402ResponseBytesCeiling}
	c := Call{Price: DefaultPrices()["x402.call"]}
	receipt := &x402Receipt{Amount: "1000"}
	for name, resp := range map[string]x402Response{
		"binary":       {status: 200, body: bytes.Repeat([]byte{0xff}, X402ResponseBytesCeiling), contentType: "application/octet-stream"},
		"control text": {status: 200, body: bytes.Repeat([]byte{0x01}, X402ResponseBytesCeiling+1), contentType: "text/plain"},
		"cut json":     {status: 200, body: []byte(rowsJSON(3000)), contentType: "application/json"},
	} {
		r, err := x.result(c, p, resp, receipt)
		if err != nil || len(r.Body) > X402StoredBodyBytes || !json.Valid(r.Body) {
			t.Fatalf("%s at the ceiling: %d bytes, %v", name, len(r.Body), err)
		}
	}
}

func TestX402CutJSON(t *testing.T) {
	for _, tc := range []struct {
		in     string
		budget int
		want   string
		ok     bool
	}{
		{`[1,2,3]`, 7, `[1,2,3]`, true},
		{`[1,2,3]`, 6, `[1,2]`, true},
		{`{"a":[1,2,3],"b":4}`, 12, `{"a":[1,2]}`, true},
		{`{"a":"long string"}`, 10, `{}`, true},
		{`"long string"`, 5, ``, false},
		{`[[[[1]]]]`, 1, ``, false},
	} {
		got, ok := x402CutJSON([]byte(tc.in), tc.budget, x402CutDepth)
		if ok != tc.ok || string(got) != tc.want || (ok && (!json.Valid(got) || len(got) > tc.budget)) {
			t.Errorf("cut %s to %d: %s %v, want %s %v", tc.in, tc.budget, got, ok, tc.want, tc.ok)
		}
	}
}
