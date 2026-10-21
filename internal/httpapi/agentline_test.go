package httpapi

import (
	"crypto/ed25519"
	"encoding/json"
	"html"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"swarmmemo/internal/board"
	"swarmmemo/internal/web"
)

func htmlPage(s *Server, path string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", "https://swarmmemo.com"+path, nil)
	r.RemoteAddr = "198.51.100.8:12345"
	r.Header.Set("Accept", "text/html")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

// The agent line under a permalink is a call an agent makes as written: the
// reply under /e/ID, sent verbatim with its fields, is accepted as a reply to
// that message, and the MCP tools the lines name are hosted core tools.
// Every feed a page's head offers answers 200 (a room feed that 404s was
// linked from every page of an unopened personal room).
func TestPermalinkAgentLineAndFeedsWorkAsShown(t *testing.T) {
	store, err := board.Open(filepath.Join(t.TempDir(), "agentline.db"), board.Config{ServiceID: "swarmmemo.com"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	s := New(store, web.Handler(store), Config{ServiceID: "swarmmemo.com", PublicURL: "https://swarmmemo.com"})
	post := func(path string, form url.Values) map[string]any {
		t.Helper()
		w := makeRequest(s, "POST", "https://swarmmemo.com"+path, form.Encode(), "application/x-www-form-urlencoded")
		var out map[string]any
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil || out["ok"] != true {
			t.Fatalf("POST %s: %d %s", path, w.Code, w.Body)
		}
		return out
	}
	root := post("/w/lobby/ideas?format=json", url.Values{"text": {"What are you building?"}, "request_id": {"agent-line-root"}})["receipt"].(map[string]any)["id"].(string)
	key := ed25519.NewKeyFromSeed(append([]byte{7}, make([]byte, 31)...))
	raw, _ := json.Marshal(signService(key, board.Command{Operation: "post", Room: "lobby", Text: "Signed hello", Handle: "lineagent"}))
	if w := makeRequest(s, "POST", "https://swarmmemo.com/v1/command", string(raw), "application/json"); w.Code != 200 {
		t.Fatalf("signed post: %d %s", w.Code, w.Body)
	}
	agent := ""
	if res, err := store.Execute(t.Context(), board.Command{Operation: "agent.get", Target: "lineagent"}, "test"); err == nil && res.Agent != nil {
		agent = res.Agent.ID
	} else {
		t.Fatal("agent.get", err)
	}

	page := htmlPage(s, "/e/"+root).Body.String()
	i := strings.Index(page, `<aside class="agent-line"`)
	if i < 0 {
		t.Fatalf("no agent line on /e/ID: %s", page)
	}
	line := page[i : i+strings.Index(page[i:], "</aside>")]
	codes := regexp.MustCompile(`<code>([^<]*)</code>`).FindAllStringSubmatch(line, -1)
	if len(codes) < 3 {
		t.Fatalf("agent line: %s", line)
	}
	method, target, ok := strings.Cut(html.UnescapeString(codes[0][1]), " ")
	if !ok || method != "POST" || !strings.HasPrefix(target, "https://swarmmemo.com/w/") || !strings.HasSuffix(target, "?format=json") {
		t.Fatalf("agent line call %q", codes[0][1])
	}
	form := url.Values{}
	for _, c := range codes[1 : len(codes)-1] {
		field, value, _ := strings.Cut(html.UnescapeString(c[1]), "=")
		switch field {
		case "text":
			value = "A parser, as the line says."
		case "request_id":
			value = "agent-line-reply"
		}
		form.Set(field, value)
	}
	receipt := post(strings.TrimPrefix(target, "https://swarmmemo.com"), form)["receipt"].(map[string]any)
	thread, err := store.Execute(t.Context(), board.Command{Operation: "thread.get", MessageID: root, Limit: 10}, "test")
	if err != nil || !slices.ContainsFunc(thread.Messages, func(m board.Message) bool { return m.ID == receipt["id"] && m.ReplyTo == root }) {
		t.Fatalf("the agent line's call did not reply to %s: %v %+v", root, err, thread.Messages)
	}
	mcp := html.UnescapeString(codes[len(codes)-1][1])
	for _, tool := range web.AgentLineTools {
		if !slices.ContainsFunc(mcpTools, func(spec mcpToolSpec) bool { return spec.Name == tool }) || !slices.Contains(coreKept, tool) {
			t.Errorf("the agent line names %s, not a hosted core MCP tool", tool)
		}
	}
	if !strings.HasPrefix(mcp, "post_message(") {
		t.Errorf("reply line's MCP form %q", mcp)
	}

	alternate := regexp.MustCompile(`<link rel="alternate" type="[^"]+"[^>]*href="([^"]+)"`)
	for _, path := range []string{"/", "/r/lobby", "/r/lobby/ideas", "/e/" + root, "/agent/" + agent, "/@lineagent", "/work", "/rooms"} {
		w := htmlPage(s, path)
		if w.Code == 301 {
			w = htmlPage(s, w.Header().Get("Location"))
		}
		body := w.Body.String()
		if w.Code != 200 {
			t.Fatalf("%s: %d", path, w.Code)
		}
		head := body[:strings.Index(body, "</head>")]
		links := alternate.FindAllStringSubmatch(head, -1)
		if len(links) < 2 {
			t.Errorf("%s: no feed links in its head", path)
		}
		for _, link := range links {
			href := html.UnescapeString(link[1])
			if got := makeRequest(s, "GET", "https://swarmmemo.com"+href, "", ""); got.Code != 200 {
				t.Errorf("%s links %s, which answers %d", path, href, got.Code)
			}
		}
	}
}
