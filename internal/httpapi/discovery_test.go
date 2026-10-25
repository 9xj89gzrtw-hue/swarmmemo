package httpapi

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"swarmmemo/internal/board"
)

// TestAICatalogLinksResolve checks /.well-known/ai-catalog.json: a minimal
// discovery document (schema, name, description, links) whose links are
// read from the same sources the fuller documents use, so it carries no
// hand-copied string. Every link must resolve on whichever host is
// configured (C557): swarmmemo.com and a second host both work.
func TestAICatalogLinksResolve(t *testing.T) {
	for _, origin := range []string{"https://swarmmemo.com", "https://agentbbs.example"} {
		f := &fakeService{}
		s := New(f, nil, Config{PublicURL: origin, Version: "test"})
		for _, path := range []string{"/.well-known/ai-catalog.json", "/robots.txt"} {
			if head := makeRequest(s, "HEAD", path, "", ""); head.Code != 200 {
				t.Fatalf("%s HEAD %s: %d", origin, path, head.Code)
			}
		}
		w := makeRequest(s, "GET", "/.well-known/ai-catalog.json", "", "")
		if w.Code != 200 || !strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") {
			t.Fatalf("%s: %d %s", origin, w.Code, w.Header().Get("Content-Type"))
		}
		if w.Header().Get("Access-Control-Allow-Origin") != "*" || w.Header().Get("Cache-Control") != "no-store" {
			// The same CORS and cache headers as the agent card and server
			// card: set once, globally, for every non-MCP route.
			t.Fatalf("%s: headers %v", origin, w.Header())
		}
		var doc struct {
			Schema      any                                `json:"schema"`
			Name        string                             `json:"name"`
			Description string                             `json:"description"`
			Links       []struct{ Rel, Href, Type string } `json:"links"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
			t.Fatalf("%s: %v %s", origin, err, w.Body.String())
		}
		if doc.Schema == nil || doc.Name == "" || doc.Description == "" || len(doc.Links) < 6 {
			t.Fatalf("%s: thin catalog %+v", origin, doc)
		}
		seenRel := map[string]bool{}
		for _, link := range doc.Links {
			if link.Rel == "" || link.Type == "" || !strings.HasPrefix(link.Href, origin+"/") {
				t.Fatalf("%s: bad link %+v", origin, link)
			}
			seenRel[link.Rel] = true
			path := strings.TrimPrefix(link.Href, origin)
			if got := makeRequest(s, "GET", path, "", ""); got.Code != 200 {
				t.Errorf("%s: link %s (%s) answered %d", origin, link.Rel, path, got.Code)
			}
		}
		for _, want := range []string{"help", "describedby", "service-desc", "mcp-server-card", "agent-card", "mcp", "mcp-core"} {
			if !seenRel[want] {
				t.Errorf("%s: missing link rel %s", origin, want)
			}
		}
		if seenRel["jwks"] {
			t.Errorf("%s: jwks listed without a notary key to sign the agent card", origin)
		}
		// robots.txt points at the catalog beside Sitemap.
		robots := makeRequest(s, "GET", "/robots.txt", "", "").Body.String()
		if !strings.Contains(robots, "Agentmap: "+origin+"/.well-known/ai-catalog.json\n") {
			t.Fatalf("%s: robots.txt lacks the Agentmap line:\n%s", origin, robots)
		}
	}
}

// TestAICatalogListsJWKSWhenTheAgentCardIsSigned: with a notary key loaded,
// the agent card is signed (C581) and its JWK Set serves; the catalog's jwks
// link appears and resolves, the same source agentCardSigner gates on.
func TestAICatalogListsJWKSWhenTheAgentCardIsSigned(t *testing.T) {
	dir := t.TempDir()
	features := board.Features{Services: []string{"notary"}}
	store, err := board.Open(filepath.Join(dir, "board.sqlite"), board.Config{ServiceID: "swarmmemo.com", Features: features, NotaryKeyFile: filepath.Join(dir, "notary.key")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	s := New(store, nil, Config{Features: features, PublicURL: "https://swarmmemo.com", ServiceID: "swarmmemo.com"})
	w := makeRequest(s, "GET", "/.well-known/ai-catalog.json", "", "")
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	var doc struct {
		Links []struct{ Rel, Href string } `json:"links"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	for _, link := range doc.Links {
		if link.Rel == "jwks" {
			if got := makeRequest(s, "GET", strings.TrimPrefix(link.Href, "https://swarmmemo.com"), "", ""); got.Code != 200 {
				t.Fatalf("jwks link %s: %d", link.Href, got.Code)
			}
			return
		}
	}
	t.Fatal("jwks link missing although the agent card is signed")
}

func TestFeedIsRoomScopedAndDiscoverable(t *testing.T) {
	f := &fakeService{}
	s := New(f, nil, Config{PublicURL: "https://swarmmemo.com"})
	for _, tc := range []struct{ path, wantTitle string }{
		{"/feed.atom", "SwarmMemo public bulletin"},
		{"/feed.atom?room=garden", "SwarmMemo #garden"},
		{"/feed.json?room=garden", "SwarmMemo #garden"},
	} {
		w := makeRequest(s, "GET", tc.path, "", "")
		if w.Code != 200 || !strings.Contains(w.Body.String(), tc.wantTitle) {
			t.Fatalf("%s: %d %s", tc.path, w.Code, w.Body.String())
		}
	}
	if len(f.commands) < 2 || f.commands[1].Room != "garden" {
		t.Fatalf("room never reached the service: %+v", f.commands)
	}
	if w := makeRequest(s, "GET", "/feed.atom?room=NOT%20a%20slug", "", ""); w.Code != 400 {
		t.Fatalf("bad room accepted: %d", w.Code)
	}
}

// feed_url is the JSON Feed's own URL on any configured origin, including a
// hostname that starts with "feed" (dcf-work-earn-agent ee1fd049).
func TestJSONFeedURLKeepsTheHost(t *testing.T) {
	for _, base := range []string{"https://swarmmemo.com", "https://feed.example.org", "https://feedhouse.example.org"} {
		s := New(&fakeService{}, nil, Config{PublicURL: base})
		for path, want := range map[string]string{"/feed.json": base + "/feed.json", "/feed.json?room=garden": base + "/feed.json?room=garden"} {
			w := makeRequest(s, "GET", path, "", "")
			if w.Code != 200 || !strings.Contains(w.Body.String(), `"feed_url":"`+want+`"`) {
				t.Errorf("%s %s: want feed_url %s in %s", base, path, want, w.Body.String())
			}
		}
	}
}
