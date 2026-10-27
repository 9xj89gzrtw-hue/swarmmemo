package web

import (
	"testing"

	"swarmmemo/internal/board"
)

// LandingKey keeps a fixed page's path and folds an entity page to its
// shape: never an ID, a room name or a query, and only landing pages.
func TestLandingKeyFoldsToThePageShape(t *testing.T) {
	for path, want := range map[string]string{
		"/":                               "/",
		"/llms.txt":                       "/llms.txt",
		"/for-agents":                     "/for-agents",
		"/for/chatgpt":                    "/for/chatgpt",
		"/tools/fetch":                    "/tools/fetch",
		"/tools/notary":                   "/tools/notary",
		"/guides/agent-board-map":         "/guides/agent-board-map",
		"/guides/Some-Post-Slug-42":       "/guides/{id}",
		"/e/01HZX3ABCDEF0123456789":       "/e/{id}",
		"/e/01HZX3ABCDEF/proof":           "/e/{id}/proof",
		"/e/01HZX3ABCDEF/a1b2c3/x/y":      "/e/{id}/{id}/x",
		"/agent/9f86d081884c7d659a2feaa0": "/agent/{id}",
		"/agent/9f86d081/trust":           "/agent/{id}/trust",
		"/r/lobby":                        "/r/{room}",
		"/r/secret-room/style":            "/r/{room}/style",
		"/a/blob.png":                     "/a/{id}",
		"/work/w_123":                     "/work/{id}",
		"/lounge/r/abc123":                "/lounge/r/{id}",
		"/e/":                             "/e/{id}",
		"/api/messages":                   "",
		"/rooms":                          "",
		"/admin/status":                   "",
		"/i/post-1.png":                   "",
	} {
		got := LandingKey(path)
		if got != want {
			t.Errorf("LandingKey(%q) = %q, want %q", path, got, want)
		}
		if got != "" && !board.ValidAssistantPath(got) {
			t.Errorf("LandingKey(%q) = %q cannot be stored", path, got)
		}
	}
	// Every fixed landing page folds to itself and can be stored.
	for path := range landingStatic() {
		if LandingPath(path) && LandingKey(path) != path {
			t.Errorf("fixed page %q folded to %q", path, LandingKey(path))
		}
		if LandingPath(path) && !board.ValidAssistantPath(path) {
			t.Errorf("fixed page %q cannot be stored", path)
		}
	}
	for _, n := range SiteNav {
		if n.Landing && n.Path != "" && (LandingKey(n.Path) != n.Path || !board.ValidAssistantPath(n.Path)) {
			t.Errorf("landing row %q folds to %q", n.Path, LandingKey(n.Path))
		}
	}
}
