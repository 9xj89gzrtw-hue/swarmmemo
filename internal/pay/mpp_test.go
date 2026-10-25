package pay

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"swarmmemo/internal/jcs"
)

// Test vectors below marked "independent" were computed outside Go
// (Python: hmac/hashlib for HMAC-SHA256 and HKDF, pycryptodome for
// Keccak-256) from the same inputs, and cross-checked by hand against the
// spec's slot layout.

var (
	testUSDC, _   = ParseEVMAddress("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913")
	testPayTo, _  = ParseEVMAddress("0x1111111111111111111111111111111111111111")
	testFrom, _   = ParseEVMAddress("0x2222222222222222222222222222222222222222")
	testOther, _  = ParseEVMAddress("0x3333333333333333333333333333333333333333")
	testRail      = Rail{Network: "eip155:8453", Asset: testUSDC, AssetName: "USD Coin", AssetVersion: "2"}
	testSecret    = []byte("0123456789abcdef0123456789abcdef")
	testRealm     = "swarmmemo.example"
	testQuote     = "1760180400.c2FsdA.bWFj"
	testExpires   = int64(1760180400) // 2025-10-11T11:00:00Z
	testNow       = testExpires - 200
	testSignature = "0x" + strings.Repeat("1f", 65)
)

func testAsk() Ask {
	return Ask{PayTo: testPayTo, Amount: 250_000, Quote: testQuote, Expires: testExpires, MaxTimeout: 300,
		Resource: "https://swarmmemo.example/v1/command", Description: "Top up 250000 SwarmMemo credits (0.25 USDC)"}
}

func testMPP(t testing.TB) mppWire {
	t.Helper()
	w, err := NewMPP(testRail, testRealm, testSecret)
	if err != nil {
		t.Fatal(err)
	}
	return w.(mppWire)
}

func code(err error) string {
	var r *Refusal
	if errors.As(err, &r) {
		return r.Code
	}
	if err == nil {
		return ""
	}
	return "other: " + err.Error()
}

// The spec's own HMAC-SHA256 test vectors (draft-httpauth-payment-01,
// "HMAC-SHA256 Test Vectors"), also recomputed independently.
func TestMPPChallengeIDSpecVectors(t *testing.T) {
	key := []byte("test-vector-secret")
	req := "eyJhbW91bnQiOiIxMDAwMDAwIn0"
	for _, v := range []struct{ header, opaque, want string }{
		{"", "", "X6v1eo7fJ76gAxqY0xN9Jd__4lUyDDYmriryOM-5FO4"},
		{"Payment-Authorization", "", "S91xi-OFGZPMs-j7GsX0FDpIkmCcZT1P9XyV58WNy_U"},
		{"Payment-Authorization", "eyJwaSI6InBpXzEyMyJ9", "CJ4X1O4aTDmS59hfdhnhBtxIQjWDOf0bcrhsswwMOW8"},
	} {
		if got := MPPChallengeID(key, "api.example.com", "tempo", "charge", req, "", "", v.header, v.opaque); got != v.want {
			t.Errorf("header %q opaque %q: id %s, want %s", v.header, v.opaque, got, v.want)
		}
	}
	// The vectors' request and opaque are JCS + base64url of these objects.
	for obj, want := range map[string]string{`{"amount":"1000000"}`: req, `{"pi":"pi_123"}`: "eyJwaSI6InBpXzEyMyJ9"} {
		var m map[string]any
		if err := json.Unmarshal([]byte(obj), &m); err != nil {
			t.Fatal(err)
		}
		raw, err := jcs.Encode(m)
		if err != nil || base64.RawURLEncoding.EncodeToString(raw) != want {
			t.Errorf("JCS of %s: %s %v", obj, raw, err)
		}
	}
}

// The evm charge spec's full example request (Appendix "Full Example:
// Permit2 Charge on MegaETH") is JCS: re-encoding its decoded form gives
// the same base64url.
func TestJCSMatchesSpecExampleRequest(t *testing.T) {
	spec := strings.Join(strings.Fields(`eyJhbW91bnQiOiIxMDAwMDAwMDAwMDAwMDAwMDAwIiwiY3
    VycmVuY3kiOiIweEZBZkRkYmIzRkM3Njg4NDk0OTcxYTc5Y2M2NU
    RDYTNFRjgyMDc5RTciLCJtZXRob2REZXRhaWxzIjp7ImNoYWluSWQ
    iOjQzMjYsImNyZWRlbnRpYWxUeXBlcyI6WyJwZXJtaXQyIl19LCJ
    yZWNpcGllbnQiOiIweDc0MmQzNUNjNjYzNEMwNTMyOTI1YTNiODQ0
    QmM5ZTc1OTVmOGZFMDAifQ`), "")
	raw, err := base64.RawURLEncoding.DecodeString(spec)
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]any{
		"amount": "1000000000000000000", "currency": "0xFAfDdbb3FC7688494971a79cc65DCa3EF82079E7",
		"recipient":     "0x742d35Cc6634C0532925a3b844Bc9e7595f8fE00",
		"methodDetails": map[string]any{"chainId": 4326, "credentialTypes": []string{"permit2"}},
	}
	got, err := jcs.Encode(m)
	if err != nil || string(got) != string(raw) {
		t.Fatalf("JCS:\n got  %s\n spec %s", got, raw)
	}
}

func TestKeccakVectors(t *testing.T) {
	for in, want := range map[string]string{
		"":    "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
		"abc": "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
	} {
		h := Keccak256([]byte(in))
		if hex.EncodeToString(h[:]) != want {
			t.Errorf("keccak256(%q)", in)
		}
	}
	// abi.encodePacked(string, string) is the bytes concatenated; the
	// evm spec's example id and realm (its printed nonce is elided).
	n := ChallengeNonce("aB3cDeF4gHiJkLmN", "api.example.com")
	if got := hex.EncodeToString(n[:]); got != "899e3a8fe6830644e150b972d4ba1fce69bcdf0bf9ea7f13d57cada71c6f281d" { // independent
		t.Fatalf("nonce %s", got)
	}
	if ChallengeNonce("ab", "c") != ChallengeNonce("a", "bc") {
		t.Fatal("encodePacked is plain concatenation")
	}
}

// Our challenge for a fixed Ask, against independently computed values.
func TestMPPChallengeVector(t *testing.T) {
	w := testMPP(t)
	if hex.EncodeToString(w.key) != "183a3beb0a5a49e703b94b1a6f1bf1a5ae1139d1b680d4af8b7c70382a6847bf" { // independent HKDF
		t.Fatalf("HKDF key %x", w.key)
	}
	const (
		wantRequest = "eyJhbW91bnQiOiIyNTAwMDAiLCJjdXJyZW5jeSI6IjB4ODMzNTg5ZkNENmVEYjZFMDhmNGM3QzMyRDRmNzFiNTRiZEEwMjkxMyIsIm1ldGhvZERldGFpbHMiOnsiY2hhaW5JZCI6ODQ1MywiY3JlZGVudGlhbFR5cGVzIjpbImF1dGhvcml6YXRpb24iXSwiZGVjaW1hbHMiOjYsInBlcm1pdDJBZGRyZXNzIjoiMHgwMDAwMDAwMDAwMjJENDczMDMwRjExNmRERUU5RjZCNDNhQzc4QkEzIn0sInJlY2lwaWVudCI6IjB4MTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMSJ9"
		wantOpaque  = "eyJxIjoiMTc2MDE4MDQwMC5jMkZzZEEuYldGaiJ9"
		wantID      = "Ltkz5Gd1T_4w_KwCP7TbQ6ZaexIQadQrayjmjR-eoYI"
		wantNonce   = "0xe61f67b6269246595c81130461f971881bf722c49ad2ebae25a6b52153d9a57d"
		wantID2     = "yODPeay8lRJWK9KCHteo0Bei9RqAwtgJuyUqc3RchDw"
		wantNonce2  = "0x35415d243930db42e4c14a5a915d1d2dd980489d345623d815cf4df58eb2f1f2"
		wantDigest  = "sha-256=:DPHN7SMZCDBuckx/q4mXRXkgMfiobG8m89MAU8I74qw=:"
	)
	h := http.Header{}
	body, err := w.Challenge(testAsk(), h)
	if err != nil {
		t.Fatal(err)
	}
	want := `Payment id="` + wantID + `", realm="swarmmemo.example", method="evm", intent="charge", request="` + wantRequest +
		`", expires="2025-10-11T11:00:00Z", opaque="` + wantOpaque + `", description="Top up 250000 SwarmMemo credits (0.25 USDC)"`
	if got := h.Get("WWW-Authenticate"); got != want {
		t.Fatalf("challenge:\n got  %s\n want %s", got, want)
	}
	if h.Get("Cache-Control") != "no-store" {
		t.Fatal("402 must be no-store")
	}
	if body["type"] != ProblemBase+"payment-required" || body["status"] != 402 || body["challengeId"] != wantID {
		t.Fatalf("body %v", body)
	}
	if challengeNonceHex(wantID, testRealm) != wantNonce {
		t.Fatal("nonce")
	}
	// With a body digest and the Payment-Authorization header selected.
	a := testAsk()
	a.Body, a.PaymentAuthorization = []byte(`{"input":"hello <world>"}`), true
	p, err := w.build(a)
	if err != nil || p.Digest != wantDigest || p.Header != "Payment-Authorization" || p.ID != wantID2 || challengeNonceHex(p.ID, p.Realm) != wantNonce2 {
		t.Fatalf("digest/header challenge: %+v %v", p, err)
	}
	// The request decodes to what we ask.
	cs, err := ParseMPPChallenges([]string{want})
	if err != nil || len(cs) != 1 {
		t.Fatal(err)
	}
	req, err := cs[0].Request()
	if err != nil || req["amount"] != "250000" || req["recipient"] != testPayTo.String() || req["currency"] != testUSDC.String() {
		t.Fatalf("request %v %v", req, err)
	}
	if md := req["methodDetails"].(map[string]any); md["chainId"] != json.Number("8453") || md["credentialTypes"].([]any)[0] != "authorization" {
		t.Fatalf("methodDetails %v", md)
	}
	if cs[0].Nonce() != wantNonce {
		t.Fatal("client nonce")
	}
}

// testCredential answers the challenge w issues for a with an authorization
// as an MPP client would sign it; mutate edits the authorization first.
func testCredential(t testing.TB, w Wire, a Ask, mutate func(au *X402AuthorizationWire, echo map[string]string)) (header string, field string) {
	t.Helper()
	h := http.Header{}
	if _, err := w.Challenge(a, h); err != nil {
		t.Fatal(err)
	}
	cs, err := ParseMPPChallenges(h.Values("WWW-Authenticate"))
	if err != nil || len(cs) != 1 {
		t.Fatalf("challenges %v %v", cs, err)
	}
	c := cs[0]
	au := X402AuthorizationWire{From: testFrom.String(), To: a.PayTo.String(), Value: "250000", ValidAfter: "0",
		ValidBefore: "1760180400", Nonce: c.Nonce()}
	if mutate != nil {
		echo := c.Params
		mutate(&au, echo)
		c = MPPChallenge{Params: echo}
	}
	v, err := c.Credential(au, testSignature, "did:pkh:eip155:8453:"+testFrom.String())
	if err != nil {
		t.Fatal(err)
	}
	field = "Authorization"
	if c.Params["header"] != "" {
		field = c.Params["header"]
	}
	return v, field
}

func parseHeader(t testing.TB, w Wire, value, field string) (Auth, error) {
	t.Helper()
	h := http.Header{}
	h.Set(field, value)
	raw, f, err := w.Credential(h)
	if err != nil {
		return Auth{}, err
	}
	return w.Parse(raw, f)
}

func TestMPPRoundTrip(t *testing.T) {
	w := testMPP(t)
	for _, payAuth := range []bool{false, true} {
		a := testAsk()
		a.PaymentAuthorization = payAuth
		a.Body = []byte(`{"amount":250000}`)
		v, field := testCredential(t, w, a, nil)
		x, err := parseHeader(t, w, v, field)
		if err != nil {
			t.Fatal(err)
		}
		if x.Wire != WireMPP || x.Quote != testQuote || x.From != testFrom || x.To != testPayTo || x.Value != 250_000 || x.Field != field {
			t.Fatalf("auth %+v", x)
		}
		if err := w.Bound(x, a, testNow); err != nil {
			t.Fatalf("bound (Payment-Authorization %v): %v", payAuth, err)
		}
		// Ready for the facilitator: the authorization and the quote.
		p := x.Payment()
		if p.Scheme != "exact" || p.Quote != testQuote || p.Nonce != x.Nonce || p.Signature != testSignature || p.From != testFrom || p.Resource != nil {
			t.Fatalf("payment %+v", p)
		}
	}
}

func TestMPPBoundRefusals(t *testing.T) {
	w := testMPP(t)
	a := testAsk()
	v, field := testCredential(t, w, a, nil)
	good, err := parseHeader(t, w, v, field)
	if err != nil {
		t.Fatal(err)
	}
	other := func(f func(*Ask)) Ask { b := testAsk(); f(&b); return b }
	cred := func(m func(au *X402AuthorizationWire, echo map[string]string)) Auth {
		v, field := testCredential(t, w, a, m)
		x, err := parseHeader(t, w, v, field)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		return x
	}
	otherKey, _ := NewMPP(testRail, testRealm, []byte("another secret, 32 bytes long..."))
	otherAsset := testRail
	otherAsset.Asset = testOther
	otherAssetWire, _ := NewMPP(otherAsset, testRealm, testSecret)
	otherChain := testRail
	otherChain.Network = "eip155:84532"
	otherChainWire, _ := NewMPP(otherChain, testRealm, testSecret)
	otherRealm, _ := NewMPP(testRail, "other.example", testSecret)
	moved := good
	moved.Field = "Payment-Authorization"
	for _, c := range []struct {
		name string
		w    Wire
		x    Auth
		a    Ask
		now  int64
		want string
	}{
		{"good", w, good, a, testNow, ""},
		{"good at expiry", w, good, a, testExpires - ValidBeforeMargin, ""},
		{"wrong payTo", w, good, other(func(b *Ask) { b.PayTo = testOther }), testNow, CodeMismatch},
		{"wrong amount", w, good, other(func(b *Ask) { b.Amount = 250_001 }), testNow, CodeMismatch},
		{"wrong asset", otherAssetWire, good, a, testNow, CodeMismatch},
		{"wrong chain", otherChainWire, good, a, testNow, CodeMismatch},
		{"wrong realm", otherRealm, good, a, testNow, CodeChallenge},
		{"other server secret", otherKey, good, a, testNow, CodeChallenge},
		{"replayed against a fresh challenge", w, good, other(func(b *Ask) { b.Quote = "1760180400.bmV3.bWFj" }), testNow, CodeChallenge},
		{"other body", w, good, other(func(b *Ask) { b.Body = []byte("{}") }), testNow, CodeMismatch},
		{"header selected but sent in Authorization", w, good, other(func(b *Ask) { b.PaymentAuthorization = true }), testNow, CodeChallenge},
		{"sent in Payment-Authorization, not selected", w, moved, a, testNow, CodeChallenge},
		{"challenge expired", w, good, a, testExpires + 1, CodeExpired},
		{"authorization lapses inside the margin", w, good, a, testExpires - ValidBeforeMargin + 1, CodeExpired},
		{"authorization to another address", w, cred(func(au *X402AuthorizationWire, _ map[string]string) { au.To = testOther.String() }), a, testNow, CodeMismatch},
		{"authorization value differs", w, cred(func(au *X402AuthorizationWire, _ map[string]string) { au.Value = "250001" }), a, testNow, CodeMismatch},
		{"random nonce (an x402 authorization)", w, cred(func(au *X402AuthorizationWire, _ map[string]string) { au.Nonce = "0x" + strings.Repeat("ab", 32) }), a, testNow, CodeMismatch},
		{"nonce for another realm", w, cred(func(au *X402AuthorizationWire, e map[string]string) {
			au.Nonce = challengeNonceHex(e["id"], "other.example")
		}), a, testNow, CodeMismatch},
		{"validAfter in the future", w, cred(func(au *X402AuthorizationWire, _ map[string]string) { au.ValidAfter = "1760180300" }), a, testNow, CodeExpired},
		{"validBefore too soon", w, cred(func(au *X402AuthorizationWire, _ map[string]string) { au.ValidBefore = "1760180210" }), a, testNow, CodeExpired},
		{"tampered id", w, cred(func(_ *X402AuthorizationWire, e map[string]string) { e["id"] = "A" + e["id"][1:] }), a, testNow, CodeChallenge},
		{"tampered expires", w, cred(func(_ *X402AuthorizationWire, e map[string]string) { e["expires"] = "2025-10-11T12:00:00Z" }), a, testNow, CodeChallenge},
		{"expires dropped", w, cred(func(_ *X402AuthorizationWire, e map[string]string) { delete(e, "expires") }), a, testNow, CodeChallenge},
		{"opaque dropped", w, cred(func(_ *X402AuthorizationWire, e map[string]string) { delete(e, "opaque") }), a, testNow, CodeChallenge},
		{"header added", w, cred(func(_ *X402AuthorizationWire, e map[string]string) { e["header"] = "Payment-Authorization" }), a, testNow, CodeChallenge},
		{"digest added", w, cred(func(_ *X402AuthorizationWire, e map[string]string) { e["digest"] = ContentDigest(nil) }), a, testNow, CodeMismatch},
		{"tampered request", w, cred(func(_ *X402AuthorizationWire, e map[string]string) { e["request"] = e["request"][:len(e["request"])-2] }), a, testNow, CodeMismatch},
		{"other method", w, cred(func(_ *X402AuthorizationWire, e map[string]string) { e["method"] = "tempo" }), a, testNow, CodeChallenge},
		{"other intent", w, cred(func(_ *X402AuthorizationWire, e map[string]string) { e["intent"] = "session" }), a, testNow, CodeChallenge},
		{"description changed (unbound, display only)", w, cred(func(_ *X402AuthorizationWire, e map[string]string) { e["description"] = "free!" }), a, testNow, ""},
	} {
		if got := code(c.w.Bound(c.x, c.a, c.now)); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
	// A replay of the very same credential against the same challenge is
	// bound (Bound is stateless): its replay key is the nonce, which the
	// tables' UNIQUE auth_nonce and the token contract each accept once,
	// and which differs for every challenge.
	again, _ := parseHeader(t, w, v, field)
	fresh := other(func(b *Ask) { b.Quote = "1760180400.bmV3.bWFj" })
	v2, f2 := testCredential(t, w, fresh, nil)
	x2, _ := parseHeader(t, w, v2, f2)
	if again.Nonce != good.Nonce || x2.Nonce == good.Nonce || w.Bound(x2, fresh, testNow) != nil {
		t.Fatal("replay key")
	}
	// An incomplete Ask is never bound.
	for _, b := range []Ask{other(func(b *Ask) { b.PayTo = EVMAddress{} }), other(func(b *Ask) { b.Amount = 0 }), other(func(b *Ask) { b.Quote = "a b" })} {
		if code(w.Bound(good, b, testNow)) != CodeMismatch {
			t.Errorf("incomplete ask %+v bound", b)
		}
		if _, err := w.Challenge(b, http.Header{}); err == nil {
			t.Errorf("incomplete ask %+v challenged", b)
		}
	}
}

func b64j(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

func TestMPPParseMalformed(t *testing.T) {
	w := testMPP(t)
	v, _ := testCredential(t, w, testAsk(), nil)
	tok := strings.TrimPrefix(v, "Payment ")
	raw, _ := base64.RawURLEncoding.DecodeString(tok)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	edit := func(f func(m map[string]any)) string {
		var c map[string]any
		_ = json.Unmarshal(raw, &c)
		f(c)
		b, _ := json.Marshal(c)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	pl := func(c map[string]any) map[string]any { return c["payload"].(map[string]any) }
	ch := func(c map[string]any) map[string]any { return c["challenge"].(map[string]any) }
	if _, err := w.Parse(tok, "Authorization"); err != nil {
		t.Fatalf("good credential: %v", err)
	}
	// Unknown fields are ignored, as the spec requires.
	if _, err := w.Parse(edit(func(c map[string]any) { c["x"] = 1; pl(c)["x"] = []any{1}; ch(c)["x"] = "y" }), "Authorization"); err != nil {
		t.Fatalf("unknown fields: %v", err)
	}
	for name, in := range map[string]string{
		"empty":           "",
		"padded":          tok + "==",
		"std alphabet":    strings.ReplaceAll(strings.ReplaceAll(tok, "-", "+"), "_", "/") + "+",
		"space inside":    tok[:10] + " " + tok[10:],
		"oversized":       strings.Repeat("A", MPPCredentialBytes+1),
		"not JSON":        b64j("hello"),
		"array":           b64j("[1]"),
		"trailing data":   b64j(string(raw) + "{}"),
		"duplicate key":   b64j(strings.Replace(string(raw), `"payload":`, `"PAYLOAD":{},"payload":`, 1)),
		"invalid utf8":    b64j(strings.Replace(string(raw), `"did:pkh`, "\"\xff:pkh", 1)),
		"no challenge":    edit(func(c map[string]any) { delete(c, "challenge") }),
		"no payload":      edit(func(c map[string]any) { delete(c, "payload") }),
		"payload permit2": edit(func(c map[string]any) { pl(c)["type"] = "permit2" }),
		"payload hash": edit(func(c map[string]any) {
			c["payload"] = map[string]any{"type": "hash", "hash": "0x" + strings.Repeat("1", 64)}
		}),
		"value number":         edit(func(c map[string]any) { pl(c)["value"] = 250000 }),
		"value zero":           edit(func(c map[string]any) { pl(c)["value"] = "0" }),
		"value leading zero":   edit(func(c map[string]any) { pl(c)["value"] = "0250000" }),
		"from zero":            edit(func(c map[string]any) { pl(c)["from"] = "0x0000000000000000000000000000000000000000" }),
		"from bad checksum":    edit(func(c map[string]any) { pl(c)["from"] = "0xAbCdEf0000000000000000000000000000000000" }),
		"nonce short":          edit(func(c map[string]any) { pl(c)["nonce"] = "0x" + strings.Repeat("ab", 31) }),
		"signature short":      edit(func(c map[string]any) { pl(c)["signature"] = "0x" + strings.Repeat("1f", 64) }),
		"validBefore huge":     edit(func(c map[string]any) { pl(c)["validBefore"] = "1000000000000" }),
		"source number":        edit(func(c map[string]any) { c["source"] = 7 }),
		"id missing":           edit(func(c map[string]any) { delete(ch(c), "id") }),
		"id empty":             edit(func(c map[string]any) { ch(c)["id"] = "" }),
		"id padded":            edit(func(c map[string]any) { ch(c)["id"] = "abc=" }),
		"realm missing":        edit(func(c map[string]any) { delete(ch(c), "realm") }),
		"realm control char":   edit(func(c map[string]any) { ch(c)["realm"] = "a\nb" }),
		"method upper":         edit(func(c map[string]any) { ch(c)["method"] = "EVM" }),
		"request not b64url":   edit(func(c map[string]any) { ch(c)["request"] = "a+b" }),
		"request number":       edit(func(c map[string]any) { ch(c)["request"] = 1 }),
		"opaque nested":        edit(func(c map[string]any) { ch(c)["opaque"] = b64j(`{"q":{"x":1}}`) }),
		"opaque bad quote":     edit(func(c map[string]any) { ch(c)["opaque"] = b64j(`{"q":"a b"}`) }),
		"opaque not b64url":    edit(func(c map[string]any) { ch(c)["opaque"] = "e30=" }),
		"opaque duplicate":     edit(func(c map[string]any) { ch(c)["opaque"] = b64j(`{"q":"a","Q":"b"}`) }),
		"challenge not object": edit(func(c map[string]any) { c["challenge"] = "x" }),
	} {
		if got := code(func() error { _, err := w.Parse(in, "Authorization"); return err }()); got != CodeInvalid {
			t.Errorf("%s: %q", name, got)
		}
	}
	// A field the credential cannot come in.
	if _, err := w.Parse(tok, "X-Payment"); code(err) != CodeInvalid {
		t.Error("credential from X-Payment parsed")
	}
}

func TestMPPCredentialHeaders(t *testing.T) {
	w := testMPP(t)
	for name, c := range map[string]struct {
		h         http.Header
		raw, fld  string
		wantError error
		wantCode  string
	}{
		"none":                    {http.Header{}, "", "", ErrNoCredential, ""},
		"bearer only":             {http.Header{"Authorization": {"Bearer abc"}}, "", "", ErrNoCredential, ""},
		"payment":                 {http.Header{"Authorization": {"Payment abc"}}, "abc", "Authorization", nil, ""},
		"scheme case":             {http.Header{"Authorization": {"payment   abc  "}}, "abc", "Authorization", nil, ""},
		"payment-authorization":   {http.Header{"Authorization": {"Bearer t"}, "Payment-Authorization": {"Payment xyz"}}, "xyz", "Payment-Authorization", nil, ""},
		"two":                     {http.Header{"Authorization": {"Payment a"}, "Payment-Authorization": {"Payment b"}}, "", "", ErrManyCredentials, ""},
		"two in one field":        {http.Header{"Authorization": {"Payment a", "Payment b"}}, "", "", ErrManyCredentials, ""},
		"bearer in payment field": {http.Header{"Payment-Authorization": {"Bearer a"}}, "", "", nil, CodeInvalid},
		"oversized":               {http.Header{"Authorization": {"Payment " + strings.Repeat("A", MPPCredentialBytes+1)}}, "", "", nil, CodeInvalid},
	} {
		raw, fld, err := w.Credential(c.h)
		switch {
		case c.wantCode != "":
			if code(err) != c.wantCode {
				t.Errorf("%s: %v", name, err)
			}
		case !errors.Is(err, c.wantError) && !(err == nil && c.wantError == nil):
			t.Errorf("%s: %v", name, err)
		case raw != c.raw || fld != c.fld:
			t.Errorf("%s: %q %q", name, raw, fld)
		}
	}
}

func TestMPPReceipt(t *testing.T) {
	w := testMPP(t)
	h := http.Header{}
	tx := "0x" + strings.Repeat("AB", 32)
	if err := w.Receipt(Settlement{Transaction: tx, Payer: testFrom, Ref: "Ltkz5Gd1T_4w_KwCP7TbQ6ZaexIQadQrayjmjR-eoYI", At: testExpires - 100}, h); err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(h.Get("Payment-Receipt"))
	want := `{"chainId":8453,"challengeId":"Ltkz5Gd1T_4w_KwCP7TbQ6ZaexIQadQrayjmjR-eoYI","method":"evm","reference":"0x` + strings.Repeat("ab", 32) + `","status":"success","timestamp":"2025-10-11T10:58:20Z"}`
	if err != nil || string(raw) != want || h.Get("Cache-Control") != "private" {
		t.Fatalf("receipt %s %v %q", raw, err, h.Get("Cache-Control"))
	}
	for _, s := range []Settlement{{Transaction: "0x12", Ref: "a", At: 1}, {Transaction: tx, Ref: "", At: 1}, {Transaction: tx, Ref: "a"}} {
		if w.Receipt(s, http.Header{}) == nil {
			t.Errorf("receipt for %+v", s)
		}
	}
}

func TestProblems(t *testing.T) {
	w := testMPP(t)
	for c, want := range map[string]struct {
		slug   string
		status int
	}{
		"payment_required": {"payment-required", 402}, CodeInvalid: {"malformed-credential", 402}, CodeChallenge: {"invalid-challenge", 402},
		"payment_replayed": {"invalid-challenge", 402}, CodeExpired: {"payment-expired", 402}, CodeMismatch: {"verification-failed", 402},
		"payment_rejected": {"verification-failed", 402}, "payment_unsettled": {"internal-payment-error", 500},
	} {
		p := w.Problem(c, "why")
		if p.Status != want.status || p.Body["type"] != ProblemBase+want.slug || p.Body["status"] != want.status || p.Body["detail"] != "why" || p.Body["title"] == "" {
			t.Errorf("%s: %+v", c, p)
		}
	}
	if p := w.Problem("rate_limited", ""); p.Status != 0 || p.Body != nil {
		t.Error("a non-payment code has a problem type")
	}
	if p := NewX402(testRail).Problem(CodeInvalid, "x"); p.Status != 0 {
		t.Error("x402 has no problem bodies")
	}
}

func TestParseAuthenticate(t *testing.T) {
	cs, err := ParseMPPChallenges([]string{
		`Bearer realm="api", Payment id="a", realm="r", method="evm", intent="charge", request="e30", description="say \"hi\" \\ ok", Basic realm="x"`,
		`Payment id=tok, realm=r, method=evm, intent=charge, request=e30,`,
	})
	if err != nil || len(cs) != 2 || cs[0].Params["description"] != `say "hi" \ ok` || cs[1].Params["id"] != "tok" {
		t.Fatalf("%+v %v", cs, err)
	}
	for _, bad := range []string{
		`Payment id="a", id="b", realm="r", method="evm", intent="charge", request="e30"`, // duplicate
		`Payment id="a, realm="r"`, // unterminated
		`Payment id="a" realm="r"`, // missing comma
		`Payment realm="r", method="evm", intent="charge", request="e30"`, // no id
		`Payment id="", realm="r", method="evm", intent="charge", request="e30"`,
		`Negotiate abc==`,              // token68
		`Payment id="a` + "\x01" + `"`, // control
		strings.Repeat("a", MPPChallengeBytes+1),
	} {
		if _, err := ParseMPPChallenges([]string{bad}); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestMPPConstructor(t *testing.T) {
	for name, f := range map[string]func() (Wire, error){
		"non-evm network": func() (Wire, error) { r := testRail; r.Network = "solana:x"; return NewMPP(r, testRealm, testSecret) },
		"zero asset":      func() (Wire, error) { r := testRail; r.Asset = EVMAddress{}; return NewMPP(r, testRealm, testSecret) },
		"realm quote":     func() (Wire, error) { return NewMPP(testRail, `a"b`, testSecret) },
		"realm url":       func() (Wire, error) { return NewMPP(testRail, "https://a.example", testSecret) },
		"short secret":    func() (Wire, error) { return NewMPP(testRail, testRealm, []byte("short")) },
	} {
		if _, err := f(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// Description is display text: control characters dropped, bounded.
	if got := displayText("a\x00b\nc\u0085d" + strings.Repeat("é", 400)); !strings.HasPrefix(got, "abcd") || len(got) > mppDescriptionBytes {
		t.Fatalf("display text %q", got)
	}
}
