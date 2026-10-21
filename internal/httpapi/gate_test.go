package httpapi

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	publicclients "swarmmemo/clients"
	"swarmmemo/internal/board"
	"swarmmemo/internal/gate"
	"swarmmemo/internal/services"
	"swarmmemo/internal/web"
)

// C325: the SwarmMemo Gate over HTTP and MCP on a real store: origin
// binding, single use, the token checked offline, the server checks in the
// docs run verbatim, and gate_solve.

func gateServer(t *testing.T) (*board.Store, *Server) {
	t.Helper()
	return hostedServerWith(t, board.Features{Services: []string{"notary"}})
}

func gatePost(s http.Handler, path, body, origin string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "https://swarmmemo.com"+path, strings.NewReader(body))
	r.RemoteAddr = "198.51.100.20:4000"
	r.Header.Set("Content-Type", "application/json")
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

func gateData(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out struct {
		OK   bool           `json:"ok"`
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || !out.OK || w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	return out.Data
}

func gateCode(t *testing.T, w *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if w.Code != status || !strings.Contains(w.Body.String(), `"code":"`+code+`"`) {
		t.Fatalf("want %d %s, got %d %s", status, code, w.Code, w.Body.String())
	}
}

func gateStatusOf(t *testing.T, s http.Handler) map[string]any {
	t.Helper()
	w := makeRequest(s, "GET", "/v1/gate/status", "", "")
	var status map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &status); err != nil || w.Code != 200 {
		t.Fatalf("status: %d %s", w.Code, w.Body.String())
	}
	return status
}

func TestGateHTTPFlow(t *testing.T) {
	_, s := gateServer(t)
	status := gateStatusOf(t, s)
	if status["ok"] != true || len(status["public_key"].(string)) != 43 || status["key_id"] == "" {
		t.Fatalf("status: %v", status)
	}
	// A page on another site: its Origin fills the origin, and the answer
	// is readable by it (CORS).
	w := gatePost(s, "/v1/gate/challenge", `{"schema":1}`, "https://shop.example")
	if w.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Fatal("the gate must be callable from any page")
	}
	ch := gateData(t, w)
	if ch["origin"] != "https://shop.example" {
		t.Fatalf("origin from the header: %v", ch)
	}
	// It cannot ask for another site's.
	gateCode(t, gatePost(s, "/v1/gate/challenge", `{"schema":1,"origin":"https://bank.example"}`, "https://shop.example"), 403, "invalid_origin")
	// swarmmemo.com's own pages and servers name it.
	if c := gateData(t, gatePost(s, "/v1/gate/challenge", `{"schema":1,"origin":"https://bank.example"}`, "https://swarmmemo.com")); c["origin"] != "https://bank.example" {
		t.Fatalf("own page: %v", c)
	}
	gateCode(t, gatePost(s, "/v1/gate/challenge", `{"schema":1}`, ""), 400, "invalid_origin")
	// The work, the token, checked offline; then the replay.
	id := ch["challenge"].(string)
	solution, _ := gate.Solve(id, gate.BitsDefault, 1<<26)
	body := fmt.Sprintf(`{"schema":1,"challenge":%q,"solution":%q}`, id, solution)
	res := gateData(t, gatePost(s, "/v1/gate/verify", body, "https://shop.example"))
	p, err := services.VerifyGateToken(status["public_key"].(string), res["token"].(string), "https://shop.example", time.Now().Unix())
	if err != nil || !p.Passed || p.Nonce != id {
		t.Fatalf("token: %+v %v", p, err)
	}
	gateCode(t, gatePost(s, "/v1/gate/verify", body, "https://shop.example"), 410, "challenge_expired")
	// Query strings, other methods, oversized bodies and unknown routes.
	gateCode(t, gatePost(s, "/v1/gate/verify?token=x", body, ""), 400, "ambiguous_command")
	if w := makeRequest(s, "GET", "/v1/gate/challenge", "", ""); w.Code != 405 {
		t.Fatalf("GET challenge: %d", w.Code)
	}
	if w := gatePost(s, "/v1/gate/verify", `{"schema":1,"challenge":"`+strings.Repeat("a", 5000)+`"}`, ""); w.Code != 413 {
		t.Fatalf("oversized: %d %s", w.Code, w.Body.String())
	}
	gateCode(t, gatePost(s, "/v1/gate/challenge", `null`, ""), 400, "invalid_request")
	gateCode(t, gatePost(s, "/v1/gate/challenge", `{"schema":1,"origin":"https://a.example","x":1}`, ""), 400, "invalid_gate_data")
	gateCode(t, gatePost(s, "/v1/gate/verify", `{"operation":"post","text":"x"}`, ""), 400, "invalid_request")
	if w := makeRequest(s, "GET", "/v1/gate/nope", "", ""); w.Code != 404 {
		t.Fatalf("unknown: %d", w.Code)
	}
}

// A signed gate.verify posted to /v1/gate/verify: the identity, with the
// work beside a key that has no standing.
func TestGateHTTPSignedVerify(t *testing.T) {
	_, s := gateServer(t)
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	ch := gateData(t, gatePost(s, "/v1/gate/challenge", `{"schema":1,"origin":"https://forum.example"}`, ""))
	solution, _ := gate.Solve(ch["challenge"].(string), gate.BitsDefault, 1<<26)
	c := board.Command{Operation: "gate.verify", Data: fmt.Sprintf(`{"schema":1,"challenge":%q,"solution":%q}`, ch["challenge"], solution),
		PublicKey: base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey)), Timestamp: time.Now().Unix(), Nonce: "gate-signed-1"}
	c.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, board.Canonical("swarmmemo.com", c)))
	raw, _ := json.Marshal(c)
	res := gateData(t, gatePost(s, "/v1/gate/verify", string(raw), ""))
	if proofs := fmt.Sprint(res["proofs"]); proofs != "[pow identity]" || len(res["subject"].(string)) != 64 {
		t.Fatalf("signed: %v", res)
	}
}

// The gate's surfaces: capabilities, OpenAPI, llms.txt, the sitemap.
func TestGateDiscovery(t *testing.T) {
	_, s := gateServer(t)
	caps := s.capabilities()
	g, ok := caps["gate"].(map[string]any)
	if !ok || g["mcp_tool"] != "gate_solve" || g["funnel_entry"] != board.GateRef {
		t.Fatalf("capabilities gate: %v", caps["gate"])
	}
	if !strings.Contains(fmt.Sprint(caps["operations"]), "gate.verify") {
		t.Fatal("operations miss gate.verify")
	}
	paths := s.openapi()["paths"].(map[string]any)
	for _, p := range []string{"/v1/gate/challenge", "/v1/gate/verify", "/v1/gate/status"} {
		if paths[p] == nil {
			t.Errorf("openapi misses %s", p)
		}
	}
	if text := s.instructionsFor(s.staticCatalog(), true); !strings.Contains(text, "/gate") || !strings.Contains(text, "gate_solve") {
		t.Fatal("llms-full.txt misses the gate")
	}
	if !strings.Contains(makeRequest(s, "GET", "/sitemap.xml", "", "").Body.String(), "/gate/agent") {
		t.Fatal("sitemap misses /gate/agent")
	}
	listed := false
	for _, tool := range s.mcpToolList() {
		listed = listed || tool.Name == "gate_solve"
	}
	if !listed {
		t.Fatal("tools/list misses gate_solve")
	}
}

// gate_solve: anonymous, the challenge and then the work; as a hosted
// identity with no standing, the same, signed.
func TestGateSolveMCP(t *testing.T) {
	_, s := gateServer(t)
	for _, path := range []string{"/mcp", ""} {
		if path == "" {
			path = "/mcp/t/" + newIdentity(t, s, "")["token"].(string)
		}
		first := mustTool(t, s, path, "", "gate_solve", map[string]any{"origin": "https://shop.example"})["data"].(map[string]any)
		pow := first["pow"].(map[string]any)
		solution, ok := gate.Solve(pow["prefix"].(string), int(pow["bits"].(float64)), 1<<26)
		if !ok {
			t.Fatal("no solution")
		}
		res := mustTool(t, s, path, "", "gate_solve", map[string]any{"challenge": first["challenge"], "solution": solution})["data"].(map[string]any)
		if res["passed"] != true || !strings.HasPrefix(res["token"].(string), "smg1.") {
			t.Fatalf("%s: %v", path, res)
		}
		if signed := strings.Contains(path, "/t/"); signed != strings.Contains(fmt.Sprint(res["proofs"]), "identity") {
			t.Fatalf("%s: proofs %v", path, res["proofs"])
		}
	}
	if _, failure := callTool(t, s, "/mcp", "", "gate_solve", map[string]any{"origin": "not an origin"}); !strings.Contains(failure, "invalid_origin") {
		t.Fatalf("bad origin: %q", failure)
	}
	// bits, the site's ask, reaches the challenge (C377-3).
	harder := mustTool(t, s, "/mcp", "", "gate_solve", map[string]any{"origin": "https://shop.example", "bits": gate.BitsDefault + 2})
	if bits := dig(harder, "data", "pow", "bits").(float64); int(bits) < gate.BitsDefault+2 {
		t.Fatalf("gate_solve bits: %v", dig(harder, "data", "pow"))
	}
}

// TestGateCheckSnippets runs /gate's server checks verbatim, but for the
// two URLs: SwarmMemo's address becomes a local server's, and your.site the
// test's origin. A good token prints pass; a token for another origin, a
// tampered one and an expired one print fail.
func TestGateCheckSnippets(t *testing.T) {
	store, s := gateServer(t)
	srv := httptest.NewServer(s)
	t.Cleanup(srv.Close)
	token := func(origin string) string {
		ctx := context.Background()
		res, err := store.Execute(ctx, board.Command{Operation: "gate.challenge", Data: `{"schema":1,"origin":"` + origin + `"}`}, "192.0.2.9")
		if err != nil {
			t.Fatal(err)
		}
		id := res.Data["challenge"].(string)
		solution, _ := gate.Solve(id, gate.BitsDefault, 1<<26)
		res, err = store.Execute(ctx, board.Command{Operation: "gate.verify", Data: fmt.Sprintf(`{"schema":1,"challenge":%q,"solution":%q}`, id, solution)}, "192.0.2.9")
		if err != nil {
			t.Fatal(err)
		}
		return res.Data["token"].(string)
	}
	good, other := token("https://your.site"), token("https://else.example")
	parts := strings.Split(good, ".")
	tampered := parts[0] + "." + parts[1] + "." + strings.Repeat("A", len(parts[2]))
	// C446: the good signature's bytes, spelled with its unused trailing bits
	// set. A lax decoder would pass it; every checker refuses it.
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	sig := parts[2]
	twin := parts[0] + "." + parts[1] + "." + sig[:len(sig)-1] + string(alphabet[strings.IndexByte(alphabet, sig[len(sig)-1])|1])
	dir := t.TempDir()
	// The Python check falls back to the client beside it when cryptography
	// is absent: "python, no cryptography" makes that import fail.
	client, _, ok := publicclients.ReadPath("/clients/python/swarmmemo.py")
	if !ok || os.WriteFile(filepath.Join(dir, "swarmmemo.py"), client, 0o600) != nil {
		t.Fatal("could not place the Python client beside the check")
	}
	const withoutCryptography = "import runpy, sys; sys.modules['cryptography'] = None; sys.argv = sys.argv[1:]; runpy.run_path(sys.argv[0], run_name='__main__')"
	for _, tc := range []struct {
		name, bin, file, src string
		pre                  []string
	}{
		{"node", "node", "check-gate.mjs", web.GateCheckNode, nil},
		{"python", "python3", "check_gate.py", web.GateCheckPython, nil},
		{"python, no cryptography", "python3", "check_gate.py", web.GateCheckPython, []string{"-c", withoutCryptography}},
	} {
		if _, err := exec.LookPath(tc.bin); err != nil {
			t.Logf("%s: no %s here", tc.name, tc.bin)
			continue
		}
		src := strings.ReplaceAll(tc.src, "https://swarmmemo.com", srv.URL)
		file := filepath.Join(dir, tc.file)
		if err := os.WriteFile(file, []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
		run := func(args ...string) ([]byte, error) {
			cmd := exec.Command(tc.bin, append(append(append([]string{}, tc.pre...), file), args...)...)
			cmd.Dir = dir
			return cmd.CombinedOutput()
		}
		for tok, want := range map[string]string{good: "pass", other: "fail", tampered: "fail", twin: "fail", "smg1.x.y": "fail"} {
			out, err := run(tok)
			if err != nil || strings.TrimSpace(string(out)) != want {
				t.Fatalf("%s %.20s…: want %s, got %q %v", tc.name, tok, want, out, err)
			}
		}
		// C325-sec: a token passes once; the same token again (a replayed
		// form post) fails, and another fresh token still passes.
		again := token("https://your.site")
		out, err := run(good, good, again)
		if err != nil || strings.Join(strings.Fields(string(out)), " ") != "pass fail pass" {
			t.Fatalf("%s replay: got %q %v", tc.name, out, err)
		}
	}
}

// C325-sec: the origin binding holds on every HTTP route that runs
// gate.challenge, not only /v1/gate/challenge: /v1/command and /c64/
// from another site's page, an opaque origin (Origin: null, a sandboxed
// frame), a second spelling of origin, and a signed challenge.
func TestGateOriginBindingEverywhere(t *testing.T) {
	_, s := gateServer(t)
	foreign := "https://evil.example"
	cmd := func(data string) string {
		raw, _ := json.Marshal(board.Command{Operation: "gate.challenge", Data: data})
		return string(raw)
	}
	// /v1/command: another site's origin is refused, its own is filled in.
	gateCode(t, gatePost(s, "/v1/command", cmd(`{"schema":1,"origin":"https://bank.example"}`), foreign), 403, "invalid_origin")
	if c := gateData(t, gatePost(s, "/v1/command", cmd(`{"schema":1}`), foreign)); c["origin"] != foreign {
		t.Fatalf("/v1/command fills the page's origin: %v", c)
	}
	// /c64/: the same.
	c64 := "/c64/" + base64.RawURLEncoding.EncodeToString([]byte(cmd(`{"schema":1,"origin":"https://bank.example"}`)))
	gateCode(t, gatePost(s, c64, "", foreign), 403, "invalid_origin")
	// An opaque origin names no site, on any route.
	gateCode(t, gatePost(s, "/v1/gate/challenge", `{"schema":1,"origin":"https://bank.example"}`, "null"), 403, "invalid_origin")
	gateCode(t, gatePost(s, "/v1/command", cmd(`{"schema":1,"origin":"https://bank.example"}`), "null"), 403, "invalid_origin")
	// The data's decoder matches names in any case: Origin is origin.
	gateCode(t, gatePost(s, "/v1/gate/challenge", `{"schema":1,"Origin":"https://bank.example"}`, foreign), 403, "invalid_origin")
	gateCode(t, gatePost(s, "/v1/gate/challenge", `{"schema":1,"origin":"`+foreign+`","ORIGIN":"https://bank.example"}`, foreign), 403, "invalid_origin")
	// The agent task is SwarmMemo's own: another site's page gets none.
	gateCode(t, gatePost(s, "/v1/gate/challenge", `{"schema":1,"mode":"agent"}`, foreign), 400, "invalid_origin")
	if c := gateData(t, gatePost(s, "/v1/gate/challenge", `{"schema":1,"mode":"agent"}`, "https://swarmmemo.com")); c["origin"] != "https://swarmmemo.com" {
		t.Fatalf("own agent challenge: %v", c)
	}
	// Servers and agents (no Origin) and swarmmemo.com's own pages name it.
	if c := gateData(t, gatePost(s, "/v1/command", cmd(`{"schema":1,"origin":"https://bank.example"}`), "")); c["origin"] != "https://bank.example" {
		t.Fatalf("server caller: %v", c)
	}
	// A signed challenge from another site's page must name its own
	// origin: the signed data cannot be rewritten.
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	signed := board.Command{Operation: "gate.challenge", Data: `{"schema":1}`, PublicKey: base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey)), Timestamp: time.Now().Unix(), Nonce: "gate-signed-challenge"}
	signed.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, board.Canonical("swarmmemo.com", signed)))
	raw, _ := json.Marshal(signed)
	gateCode(t, gatePost(s, "/v1/command", string(raw), foreign), 403, "invalid_origin")
}

// C348: /v1/gate/status says what raising standing from a gate earns, from
// the trust parameters in effect, and /capabilities lists the embed's
// attributes; with trust off, standing is said not to count.
func TestGateStatusStanding(t *testing.T) {
	_, off := gateServer(t)
	if st, _ := gateStatusOf(t, off)["standing"].(map[string]any); st == nil || st["counted"] != false {
		t.Fatalf("trust off: %v", st)
	}
	_, s := hostedServerWith(t, board.Features{Services: []string{"notary"}, Trust: board.TrustOn})
	st, _ := gateStatusOf(t, s)["standing"].(map[string]any)
	pow, _ := st["pow"].(map[string]any)
	if st["counted"] != true || pow == nil || pow["units_per_cent"] != float64(2158000) || pow["ceiling_cents"] != float64(50) || pow["unit_hashes"] != float64(1<<20) ||
		pow["per_day"] != float64(board.StandingPowPerDay) || st["wallet_cents"] != float64(50) {
		t.Fatalf("standing: %v", st)
	}
	now := time.Now().Unix()
	if at := int64(st["counts_at"].(float64)); at <= now || at > now+86400+int64(board.TrustRunAfter.Seconds()) || (at-int64(board.TrustRunAfter.Seconds()))%86400 != 0 {
		t.Fatalf("counts_at %d", at)
	}
	g := s.capabilities()["gate"].(map[string]any)
	raw, _ := json.Marshal(g["embed"])
	for _, attr := range []string{"data-min", "data-bits", "data-mode", "data-fail", "invisible"} {
		if !strings.Contains(string(raw), attr) {
			t.Errorf("capabilities gate.embed misses %s", attr)
		}
	}
	if !strings.Contains(fmt.Sprint(g["ways_through"]), "way=earn") {
		t.Fatalf("ways_through: %v", g["ways_through"])
	}
}
