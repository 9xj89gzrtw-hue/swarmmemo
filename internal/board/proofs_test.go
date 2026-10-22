package board

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"swarmmemo/internal/proofs"
	"swarmmemo/internal/services"
	"swarmmemo/internal/trust"
)

// C326 on the real engine: the providers' kinds through standing.challenge,
// identity.link, the rechecker, the OAuth and Telegram browser flow and the
// bond, with every outside API faked (proofs.Config.TestBaseURL).

// providerFake is one httptest server for every provider API the board
// calls: the first path segment is the host.
type providerFake struct {
	mu     sync.Mutex
	srv    *httptest.Server
	routes map[string]http.HandlerFunc
}

func newProviderFake(t *testing.T) *providerFake {
	f := &providerFake{routes: map[string]http.HandlerFunc{}}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		h := f.routes[r.Method+" "+r.URL.EscapedPath()]
		f.mu.Unlock()
		if h == nil {
			http.NotFound(w, r)
			return
		}
		h(w, r)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *providerFake) json(method, path string, v any) {
	f.on(method, path, func(w http.ResponseWriter, _ *http.Request) { _ = json.NewEncoder(w).Encode(v) })
}

func (f *providerFake) on(method, path string, h http.HandlerFunc) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.routes[method+" "+path] = h
}

func (f *providerFake) registry(c proofs.Config) *proofs.Registry {
	c.Client, c.TestBaseURL = f.srv.Client(), f.srv.URL
	return proofs.New(c)
}

func proofStore(t *testing.T, reg *proofs.Registry) *Store {
	t.Helper()
	return openTest(t, Config{Features: Features{Trust: TrustOn}, Proofs: reg, PublicURL: "https://swarmmemo.test"})
}

func TestProofChallengeKinds(t *testing.T) {
	f := newProviderFake(t)
	s := proofStore(t, f.registry(proofs.Config{OAuth: map[string]proofs.OAuthCredentials{"google": {ClientID: "gid", ClientSecret: "gsecret"}}}))
	alice := keyFor(201)
	postAs(t, s, alice, Command{Room: "lobby", Text: "alice", RequestID: "pc-alice"})
	ch := challenge(t, s, alice, map[string]any{"kind": "google"})
	nonce := ch["nonce"].(string)
	if ch["auth_url"] != "https://swarmmemo.test/proofs/oauth/google/start?state="+nonce || ch["expires_at"].(int64) != testTime+proofs.OAuthTTL {
		t.Fatalf("google: %v", ch)
	}
	// A provider without credentials is disabled; a browser kind takes no value.
	fails(t, s, standingCmd(s, alice, "standing.challenge", map[string]any{"schema": 1, "kind": "x"}), "proof_disabled")
	fails(t, s, standingCmd(s, alice, "standing.challenge", map[string]any{"schema": 1, "kind": "google", "value": "me"}), "invalid_standing")
	// Statement kinds bind kind, service, key, value and nonce.
	ch = challenge(t, s, alice, map[string]any{"kind": "pypi", "value": "Swarm_Tool"})
	if ch["value"] != "swarm-tool" || ch["statement"] != proofs.Statement("pypi", "swarmmemo.com", keyID(alice), "swarm-tool", ch["nonce"].(string)) {
		t.Fatalf("pypi: %v", ch)
	}
	fails(t, s, standingCmd(s, alice, "standing.challenge", map[string]any{"schema": 1, "kind": "npm"}), "invalid_standing")
	fails(t, s, standingCmd(s, alice, "standing.challenge", map[string]any{"schema": 1, "kind": "npm", "value": "../etc"}), "invalid_link_value")
	// No challenge for a domain or an ENS name; a bond is off without its rails.
	for _, kind := range []string{"domain", "ens", "nope"} {
		fails(t, s, standingCmd(s, alice, "standing.challenge", map[string]any{"schema": 1, "kind": kind, "value": "a.eth"}), "invalid_standing")
	}
	fails(t, s, standingCmd(s, alice, "standing.challenge", map[string]any{"schema": 1, "kind": "bond", "usdc": "2"}), "bond_unavailable")
	// identity.link cannot claim a browser kind.
	fails(t, s, standingCmd(s, alice, "identity.link", map[string]any{"schema": 1, "kind": "google", "value": "1080001"}), "proof_browser_only")
	// Every kind is listed with its status.
	caps := s.RaiseCapabilities()["roots"].(map[string]any)
	if caps["google"].(map[string]any)["status"] != "enabled" || caps["x"].(map[string]any)["status"] != "disabled-no-credentials" ||
		caps["bond"].(map[string]any)["status"] != "disabled-no-credentials" || caps["npm"].(map[string]any)["cap_cents"] != int64(200) {
		t.Fatalf("capabilities: %v", caps)
	}
	// The C144 kinds keep their challenge lifetimes.
	for kind, ttl := range map[string]int64{"wallet": StandingWalletTTL, "github": StandingGitHubTTL, "pow": StandingPowTTL} {
		p, _ := proofs.Default.Get(kind)
		if p.Spec().ChallengeTTL != ttl {
			t.Errorf("%s ttl %d, want %d", kind, p.Spec().ChallengeTTL, ttl)
		}
	}
}

// googleFake answers Google's token and userinfo endpoints: only the code
// "good" with the verifier the board derives for state, and the registered
// redirect URI.
func googleFake(f *providerFake, s *Store, sub string) {
	f.on("POST", "/oauth2.googleapis.com/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		state, good := strings.CutPrefix(r.PostForm.Get("code"), "good-")
		if !good || r.PostForm.Get("code_verifier") != proofs.PKCEVerifier(s.proofKey, state) ||
			r.PostForm.Get("redirect_uri") != "https://swarmmemo.test/proofs/oauth/google/callback" || r.PostForm.Get("client_secret") != "gsecret" {
			http.Error(w, `{"error":"invalid_grant"}`, 400)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "tok-secret-123", "token_type": "Bearer"})
	})
	f.on("GET", "/openidconnect.googleapis.com/v1/userinfo", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok-secret-123" {
			http.Error(w, "{}", 401)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"sub": sub, "email": "person@example.com", "name": "A Person"})
	})
}

// The OAuth flow's security cases: the state is single use, bound to the
// key that asked and to its kind, expires, and the PKCE verifier is derived
// (never stored); nothing but the account id and inputs is kept.
func TestOAuthProofFlow(t *testing.T) {
	f := newProviderFake(t)
	creds := map[string]proofs.OAuthCredentials{"google": {ClientID: "gid", ClientSecret: "gsecret"}, "discord": {ClientID: "did", ClientSecret: "dsecret"}}
	s := proofStore(t, f.registry(proofs.Config{OAuth: creds}))
	googleFake(f, s, "1080001")
	alice, bob := keyFor(202), keyFor(203)
	postAs(t, s, alice, Command{Room: "lobby", Text: "alice", RequestID: "of-alice"})
	postAs(t, s, bob, Command{Room: "lobby", Text: "bob", RequestID: "of-bob"})
	state := challenge(t, s, alice, map[string]any{"kind": "google"})["nonce"].(string)

	v, err := s.ProofStart(testContext, "google", state)
	if err != nil || v.Agent != keyID(alice) {
		t.Fatalf("start: %+v %v", v, err)
	}
	u, _ := url.Parse(v.AuthURL)
	q := u.Query()
	if q.Get("state") != state || q.Get("code_challenge") != proofs.PKCEChallenge(proofs.PKCEVerifier(s.proofKey, state)) || q.Get("code_challenge_method") != "S256" ||
		q.Get("redirect_uri") != "https://swarmmemo.test/proofs/oauth/google/callback" || q.Get("scope") != "openid" || strings.Contains(v.AuthURL, "gsecret") {
		t.Fatalf("auth url %s", v.AuthURL)
	}
	// The verifier is never stored: derived from the state under the key.
	if strings.Contains(dumpTable(t, s, "standing_challenges"), proofs.PKCEVerifier(s.proofKey, state)) || strings.Contains(dumpTable(t, s, "standing_challenges"), state) {
		t.Fatal("the state or its verifier is stored")
	}
	// Another kind's flow, a malformed or unknown state, refused.
	for _, c := range []struct{ kind, state, code string }{{"discord", state, "invalid_challenge"}, {"google", "zz", "invalid_challenge"},
		{"google", strings.Repeat("0", 32), "invalid_challenge"}, {"x", state, "proof_disabled"}, {"github", state, "not_found"}} {
		if _, err := s.ProofStart(testContext, c.kind, c.state); errCode(err) != c.code {
			t.Errorf("start %s %q: %v, want %s", c.kind, c.state, err, c.code)
		}
		if _, err := s.ProofCallback(testContext, c.kind, c.state, "good-"+c.state, nil); errCode(err) != c.code {
			t.Errorf("callback %s %q: %v, want %s", c.kind, c.state, err, c.code)
		}
	}
	// A refused code spends the state: it cannot be retried with another code.
	if _, err = s.ProofCallback(testContext, "google", state, "bad", nil); errCode(err) != "proof_failed" {
		t.Fatalf("bad code: %v", err)
	}
	if _, err = s.ProofCallback(testContext, "google", state, "good-"+state, nil); errCode(err) != "challenge_used" {
		t.Fatalf("replay after a failure: %v", err)
	}
	// The real flow links the account to the key that asked, once.
	state = challenge(t, s, alice, map[string]any{"kind": "google"})["nonce"].(string)
	linked, err := s.ProofCallback(testContext, "google", state, "good-"+state, nil)
	if err != nil || linked.Agent != keyID(alice) || linked.Root != "google:1080001" || linked.Value != "1080001" || linked.AddsCents != 50 {
		t.Fatalf("callback: %+v %v", linked, err)
	}
	if _, err = s.ProofCallback(testContext, "google", state, "good-"+state, nil); errCode(err) != "challenge_used" {
		t.Fatalf("replay: %v", err)
	}
	links := agentLinks(t, s, alice).Links
	if len(links) != 1 || links[0].Kind != "google" || links[0].Value != "1080001" || links[0].State != "verified" || links[0].Method != "oauth2-pkce" {
		t.Fatalf("links %+v", links)
	}
	if len(agentLinks(t, s, bob).Links) != 0 {
		t.Fatal("bob got a link")
	}
	for _, table := range []string{"identity_links", "standing_assessments", "standing_challenges", "audit"} {
		if d := dumpTable(t, s, table); strings.Contains(d, "tok-secret") || strings.Contains(d, "person@example.com") || strings.Contains(d, "A Person") || strings.Contains(d, "gsecret") {
			t.Fatalf("%s keeps a token, an email, a name or the secret: %s", table, d)
		}
	}
	// Expiry: a state older than its TTL starts and completes nothing.
	state = challenge(t, s, bob, map[string]any{"kind": "google"})["nonce"].(string)
	s.now = func() time.Time { return time.Unix(testTime+proofs.OAuthTTL, 0) }
	if _, err = s.ProofStart(testContext, "google", state); errCode(err) != "challenge_expired" {
		t.Fatalf("expired start: %v", err)
	}
	if _, err = s.ProofCallback(testContext, "google", state, "good-"+state, nil); errCode(err) != "challenge_expired" {
		t.Fatalf("expired callback: %v", err)
	}
	// The trust run counts the Google root at its row (the next day's run:
	// its as-of time is the day's start).
	s.now = func() time.Time { return time.Unix(testTime+86400+3600, 0) }
	if _, err = s.RunTrust(testContext); err != nil {
		t.Fatal(err)
	}
	var way StandingWay
	for _, w := range run(t, s, Command{Operation: "standing.ways", Target: keyID(alice)}).Data["ways"].([]StandingWay) {
		if w.Kind == "google" {
			way = w
		}
	}
	if way.State != "verified" || way.Root != "google:1080001" || way.AssessedCents == nil || *way.AssessedCents != 50 || way.CountedCents == nil || *way.CountedCents != 50 || way.Status != "enabled" {
		t.Fatalf("google way: %+v", way)
	}
	// The rechecker re-assesses without calling Google (no token is kept).
	f.on("POST", "/oauth2.googleapis.com/token", func(w http.ResponseWriter, _ *http.Request) { t.Error("the recheck called the provider") })
	if out := proofChecker("google")(s, testContext, keyID(alice), "1080001", ""); out != linkPassed {
		t.Fatalf("recheck: %v", out)
	}
}

// telegramSigned is a login widget answer signed with token's key.
func telegramSigned(token string, fields map[string]string) url.Values {
	v := url.Values{}
	var lines []string
	for k, x := range fields {
		v.Set(k, x)
		lines = append(lines, k+"="+x)
	}
	sort.Strings(lines)
	key := sha256.Sum256([]byte(token))
	mac := hmac.New(sha256.New, key[:])
	mac.Write([]byte(strings.Join(lines, "\n")))
	v.Set("hash", hex.EncodeToString(mac.Sum(nil)))
	return v
}

func i64(n int64) string { return strconv.FormatInt(n, 10) }

// Telegram's widget through the same state: its signed fields, the
// board's state beside them.
func TestTelegramProofFlow(t *testing.T) {
	s := proofStore(t, proofs.New(proofs.Config{TelegramBotToken: "42:token", TelegramBot: "swarmmemo_bot"}))
	alice := keyFor(204)
	postAs(t, s, alice, Command{Room: "lobby", Text: "alice", RequestID: "tg-alice"})
	state := challenge(t, s, alice, map[string]any{"kind": "telegram"})["nonce"].(string)
	v, err := s.ProofStart(testContext, "telegram", state)
	if err != nil || v.Bot != "swarmmemo_bot" || v.CallbackURL != "https://swarmmemo.test/proofs/oauth/telegram/callback?state="+state {
		t.Fatalf("start %+v %v", v, err)
	}
	fields := telegramSigned("42:token", map[string]string{"id": "5550001", "first_name": "A", "auth_date": i64(testTime - 5)})
	if _, err = s.ProofCallback(testContext, "telegram", state, "", telegramSigned("1:other", map[string]string{"id": "5550001", "auth_date": i64(testTime)})); errCode(err) != "proof_failed" {
		t.Fatalf("forged: %v", err)
	}
	state = challenge(t, s, alice, map[string]any{"kind": "telegram"})["nonce"].(string)
	linked, err := s.ProofCallback(testContext, "telegram", state, "", fields)
	if err != nil || linked.Root != "telegram:5550001" {
		t.Fatalf("linked %+v %v", linked, err)
	}
}

// npm through identity.link and the rechecker: claimed, then verified when
// the registry shows the statement; removed by a later release, it lapses.
func TestPackageProofRecheck(t *testing.T) {
	f := newProviderFake(t)
	s := proofStore(t, f.registry(proofs.Config{}))
	alice := keyFor(205)
	postAs(t, s, alice, Command{Room: "lobby", Text: "alice", RequestID: "np-alice"})
	ch := challenge(t, s, alice, map[string]any{"kind": "npm", "value": "swarm-tool"})
	statement := ch["statement"].(string)
	link := standingCmd(s, alice, "identity.link", map[string]any{"schema": 1, "kind": "npm", "value": "swarm-tool", "nonce": ch["nonce"]})
	fails(t, s, standingCmd(s, alice, "identity.link", map[string]any{"schema": 1, "kind": "npm", "value": "swarm-tool", "nonce": ch["nonce"], "proof": "x"}), "invalid_link_proof")
	res := run(t, s, link).Data
	if res["state"] != "claimed" || res["statement"] != statement {
		t.Fatalf("link %v", res)
	}
	fails(t, s, standingCmd(s, alice, "identity.link", map[string]any{"schema": 1, "kind": "npm", "value": "swarm-tool", "nonce": ch["nonce"]}), "challenge_used")
	created := time.Unix(testTime-800*86400, 0).UTC().Format(time.RFC3339)
	f.json("GET", "/registry.npmjs.org/swarm-tool/latest", map[string]any{"name": "swarm-tool", "swarmmemo": statement})
	f.json("GET", "/registry.npmjs.org/swarm-tool", map[string]any{"time": map[string]string{"created": created}})
	f.json("GET", "/api.npmjs.org/downloads/point/last-month/swarm-tool", map[string]any{"downloads": 4000})
	check := proofChecker("npm")
	var proof string
	if err := s.db.QueryRow("SELECT proof FROM identity_links WHERE agent=? AND kind='npm'", keyID(alice)).Scan(&proof); err != nil {
		t.Fatal(err)
	}
	if out := check(s, testContext, keyID(alice), "swarm-tool", proof); out != linkPassed {
		t.Fatalf("check %v", out)
	}
	var root string
	var assessed int64
	if err := s.db.QueryRow("SELECT root,assessed FROM standing_assessments WHERE agent=? AND kind='npm'", keyID(alice)).Scan(&root, &assessed); err != nil || root != "npm:swarm-tool" || assessed < 150 {
		t.Fatalf("assessment %s %d %v", root, assessed, err)
	}
	f.json("GET", "/registry.npmjs.org/swarm-tool/latest", map[string]any{"name": "swarm-tool", "description": "gone"})
	if out := check(s, testContext, keyID(alice), "swarm-tool", proof); out != linkFailed {
		t.Fatalf("recheck without the statement: %v", out)
	}
	f.on("GET", "/registry.npmjs.org/swarm-tool/latest", func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "down", 503) })
	if out := check(s, testContext, keyID(alice), "swarm-tool", proof); out != linkUnreachable {
		t.Fatalf("outage: %v", out)
	}
	// ENS needs a verified wallet link: without one the check fails.
	run(t, s, standingCmd(s, alice, "identity.link", map[string]any{"schema": 1, "kind": "ens", "value": "alice.eth"}))
	if out := proofChecker("ens")(s, testContext, keyID(alice), "alice.eth", ""); out != linkFailed {
		t.Fatalf("ens without a wallet: %v", out)
	}
}

// ---- the bond ----------------------------------------------------------------

func bondStore(t *testing.T) (*Store, *fakeFacilitator, *fakeChain) {
	t.Helper()
	fac := &fakeFacilitator{}
	chain := &fakeChain{head: 1000, txs: map[string]fakeTx{}}
	srv := httptest.NewServer(chain)
	t.Cleanup(srv.Close)
	reader, err := services.NewUSDCChain("https://rpc.example.org/base")
	if err != nil {
		t.Fatal(err)
	}
	reader.UseTestRPC(srv.Client(), srv.URL)
	s, err := Open(filepath.Join(t.TempDir(), "bond.sqlite"), Config{Features: Features{Trust: TrustOn}, Topup: topupConfig(t, fac, ""), WorkUSDC: reader})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	s.now = func() time.Time { return time.Unix(testTime, 0) }
	return s, fac, chain
}

func bondCmd(s *Store, key ed25519.PrivateKey, data map[string]any) Command {
	data["schema"], data["kind"] = 1, "bond"
	return standingCmd(s, key, "standing.challenge", data)
}

// bondQuoteFor asks for a bond of usdc and returns the 402's requirement.
func bondQuoteFor(t *testing.T, s *Store, key ed25519.PrivateKey, usdc string) map[string]any {
	t.Helper()
	_, e := topupExec(s, testContext, bondCmd(s, key, map[string]any{"usdc": usdc}))
	if e == nil || e.Code != "payment_required" || e.Status != 402 {
		t.Fatalf("quote: %+v", e)
	}
	raw, _ := base64.StdEncoding.DecodeString(e.Details.(map[string]any)["payment_required"].(string))
	var required struct {
		Accepts []map[string]any `json:"accepts"`
	}
	if err := json.Unmarshal(raw, &required); err != nil || len(required.Accepts) != 1 {
		t.Fatalf("PAYMENT-REQUIRED %s", raw)
	}
	return required.Accepts[0]
}

func postBond(t *testing.T, s *Store, key ed25519.PrivateKey, usdc string, nonce byte) map[string]any {
	t.Helper()
	accepted := bondQuoteFor(t, s, key, usdc)
	res := run(t, s, bondCmd(s, key, map[string]any{"usdc": usdc, "payment": pay(t, accepted, nonce, nil)}))
	return res.Data["bond"].(map[string]any)
}

func bondWayOf(t *testing.T, s *Store, key ed25519.PrivateKey) StandingWay {
	t.Helper()
	for _, w := range run(t, s, Command{Operation: "standing.ways", Target: keyID(key)}).Data["ways"].([]StandingWay) {
		if w.Kind == "bond" {
			return w
		}
	}
	t.Fatal("no bond way")
	return StandingWay{}
}

func TestBondDepositRefundSettle(t *testing.T) {
	s, fac, chain := bondStore(t)
	alice := keyFor(206)
	postAs(t, s, alice, Command{Room: "lobby", Text: "alice", RequestID: "bd-alice"})
	fails(t, s, bondCmd(s, alice, map[string]any{"usdc": "0.50"}), "bond_amount")
	fails(t, s, bondCmd(s, alice, map[string]any{"usdc": "5.01"}), "bond_amount")
	bond := postBond(t, s, alice, "2.00", 1)
	id := bond["id"].(string)
	if bond["state"] != "held" || bond["cents"] != int64(200) || bond["payer"] != topupPayer || bond["pay_to"] != topupPayTo || bond["root"] != "bond:"+id {
		t.Fatalf("bond %v", bond)
	}
	if _, settles := fac.counts(); settles != 1 {
		t.Fatalf("settles %d", settles)
	}
	// One bond at a time; a payment replayed pays nothing twice.
	fails(t, s, bondCmd(s, alice, map[string]any{"usdc": "1.00"}), "bond_open")
	// The next day's trust run counts it at face value.
	s.now = func() time.Time { return time.Unix(testTime+86400+3600, 0) }
	if _, err := s.RunTrust(testContext); err != nil {
		t.Fatal(err)
	}
	w := bondWayOf(t, s, alice)
	if w.State != "verified" || w.CountedCents == nil || *w.CountedCents != 200 || w.Status != "enabled" {
		t.Fatalf("bond way %+v", w)
	}
	// Refund: not before the cooling period.
	fails(t, s, bondCmd(s, alice, map[string]any{"action": "refund"}), "bond_cooling")
	later := testTime + 31*86400
	s.now = func() time.Time { return time.Unix(later, 0) }
	res := run(t, s, bondCmd(s, alice, map[string]any{"action": "refund"})).Data["bond"].(map[string]any)
	refund := res["refund"].(map[string]any)
	if res["state"] != "refund_owed" || refund["owed_to"] != topupPayer {
		t.Fatalf("refund %v", res)
	}
	owed, err := s.OwedBonds(testContext)
	if err != nil || len(owed) != 1 || owed[0]["id"] != id || !strings.Contains(owed[0]["settle"].(string), id) {
		t.Fatalf("owed %v %v", owed, err)
	}
	// Settle: the steward's payment on chain, checked as work.settle is.
	settle := func(hash string) Command {
		return bondCmd(s, alice, map[string]any{"action": "settle", "id": id, "tx_hash": hash})
	}
	chain.add(txHash(1), fakeTx{status: "0x1", block: 990, blockTime: later + 60, logs: []map[string]any{transferLog(s.config.WorkUSDC.Asset.String(), usdcOther, topupPayer, 2_000_000)}})
	fails(t, s, settle(txHash(1)), "settle_sender_unlinked")
	chain.add(txHash(2), fakeTx{status: "0x1", block: 990, blockTime: later + 60, logs: []map[string]any{transferLog(s.config.WorkUSDC.Asset.String(), topupPayTo, topupPayer, 1_000_000)}})
	fails(t, s, settle(txHash(2)), "settle_amount_short")
	chain.add(txHash(3), fakeTx{status: "0x1", block: 980, blockTime: later - 60, logs: []map[string]any{transferLog(s.config.WorkUSDC.Asset.String(), topupPayTo, topupPayer, 2_000_000)}})
	fails(t, s, settle(txHash(3)), "settle_tx_before_work")
	chain.add(txHash(4), fakeTx{status: "0x1", block: 990, blockTime: later + 60, logs: []map[string]any{transferLog(s.config.WorkUSDC.Asset.String(), topupPayTo, topupPayer, 2_000_000)}})
	done := run(t, s, settle(txHash(4))).Data["bond"].(map[string]any)
	if done["state"] != "refunded" || done["refund"].(map[string]any)["transaction"] != txHash(4) {
		t.Fatalf("settled %v", done)
	}
	// One transaction settles one item: the same hash again is a no-op
	// answer for this bond and refused for any other.
	run(t, s, settle(txHash(4)))
	if n := sqlCount(t, s, "SELECT count(*) FROM proof_bonds WHERE state='refunded'"); n != 1 {
		t.Fatalf("refunded %d", n)
	}
	// A refunded bond counts no more; a new one may be posted.
	s.now = func() time.Time { return time.Unix(later+86400+3600, 0) }
	if _, err := s.RunTrust(testContext); err != nil {
		t.Fatal(err)
	}
	if w = bondWayOf(t, s, alice); w.State != "refunded" || (w.CountedCents != nil && *w.CountedCents != 0) {
		t.Fatalf("after refund %+v", w)
	}
}

// A penalty burns a held bond: the run prices its root 0 and the refund is
// refused, after the penalty too.
func TestBondBurnedByPenalty(t *testing.T) {
	s, _, _ := bondStore(t)
	mallory := keyFor(207)
	postAs(t, s, mallory, Command{Room: "lobby", Text: "mallory", RequestID: "bb-mallory"})
	bond := postBond(t, s, mallory, "5.00", 9)
	s.now = func() time.Time { return time.Unix(testTime+86400+3600, 0) }
	if _, err := s.RunTrust(testContext); err != nil {
		t.Fatal(err)
	}
	if _, err := trust.NewPenalty(testContext, s.db, trust.TriggerOverride, []string{keyID(mallory)}, "a test penalty", "test", "operator", testTime+86400+3600); err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return time.Unix(testTime+2*86400+3600, 0) }
	if _, err := s.RunTrust(testContext); err != nil {
		t.Fatal(err)
	}
	if burned, err := bondBurned(testContext, s.db, bond["root"].(string)); err != nil || !burned {
		t.Fatalf("burned %v %v", burned, err)
	}
	if w := bondWayOf(t, s, mallory); w.State != "burned" {
		t.Fatalf("way %+v", w)
	}
	// While the penalty is open, and after it ends, no refund.
	s.now = func() time.Time { return time.Unix(testTime+400*86400, 0) }
	fails(t, s, bondCmd(s, mallory, map[string]any{"action": "refund"}), "bond_burned")
}

// A penalty that burns a bond after its refund was asked for (the nightly
// trust run) leaves it owed nothing: the steward's owed list drops it, the
// way shows it burned and the settle is refused (round 7, newbotlabor).
func TestBondBurnedAfterRefundIsNotRefunded(t *testing.T) {
	s, _, chain := bondStore(t)
	mallory := keyFor(208)
	postAs(t, s, mallory, Command{Room: "lobby", Text: "mallory", RequestID: "bbr-mallory"})
	bond := postBond(t, s, mallory, "3.00", 11)
	id := bond["id"].(string)
	s.now = func() time.Time { return time.Unix(testTime+86400+3600, 0) }
	if _, err := s.RunTrust(testContext); err != nil {
		t.Fatal(err)
	}
	day := (testTime/86400 + 31) * 86400
	later := day + 600
	s.now = func() time.Time { return time.Unix(later, 0) }
	if res := run(t, s, bondCmd(s, mallory, map[string]any{"action": "refund"})).Data["bond"].(map[string]any); res["state"] != "refund_owed" {
		t.Fatalf("refund %v", res)
	}
	// The race (a refund landing while the nightly run computes, the run's
	// penalty then burning the bond's root) leaves an applied penalty that
	// names the root of a refund_owed bond: written here directly.
	if _, err := s.db.Exec(`INSERT INTO trust_penalty_log(id,trigger,state,members,reason,author,burned,starts_at,created_at) VALUES('pen-race','override','applied',?,'a test penalty','operator',?,?,?)`,
		`["`+keyID(mallory)+`"]`, `["bond:`+id+`"]`, later+60, later+60); err != nil {
		t.Fatal(err)
	}
	if burned, err := bondBurned(testContext, s.db, "bond:"+id); err != nil || !burned {
		t.Fatalf("burned %v %v", burned, err)
	}
	if owed, err := s.OwedBonds(testContext); err != nil || len(owed) != 0 {
		t.Fatalf("owed %v %v", owed, err)
	}
	if w := bondWayOf(t, s, mallory); w.State != "burned" {
		t.Fatalf("way %+v", w)
	}
	chain.add(txHash(5), fakeTx{status: "0x1", block: 990, blockTime: day + 3700, logs: []map[string]any{transferLog(s.config.WorkUSDC.Asset.String(), topupPayTo, topupPayer, 3_000_000)}})
	fails(t, s, bondCmd(s, mallory, map[string]any{"action": "settle", "id": id, "tx_hash": txHash(5)}), "bond_burned")
	if n := sqlCount(t, s, "SELECT count(*) FROM proof_bonds WHERE state='refunded'"); n != 0 {
		t.Fatalf("refunded %d", n)
	}
}
