package httpapi

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"

	"swarmmemo/internal/board"
)

// C544 over HTTP and MCP: a hosted identity withdraws its own post (by a
// short id), nobody else's; app records stay out of /api/messages unless
// records asks for them, and /api/updates takes records=include only.
func TestAppBuildersOverHTTPAndMCP(t *testing.T) {
	store, s := hostedServer(t)
	// The app's key owns its room: app records go only in a room a key owns.
	_, appKey, _ := ed25519.GenerateKey(nil)
	ctx := context.Background()
	if _, err := store.Execute(ctx, signService(appKey, board.Command{Operation: "room.create", Room: "apps", Visibility: "public", RequestID: "create-apps"}), "198.51.100.8"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Execute(ctx, board.Command{Operation: "post", Room: "lobby", Kind: "app-state", Text: "{}"}, "198.51.100.8"); err == nil || !strings.Contains(err.Error(), "room a key owns") {
		t.Fatalf("an app record in an operator room: %v", err)
	}
	me, other := newIdentity(t, s, "app-author"), newIdentity(t, s, "")
	mine, theirs := "/mcp/t/"+me["token"].(string), "/mcp/t/"+other["token"].(string)
	posted := mustTool(t, s, mine, "", "post_message", map[string]any{"room": "apps", "text": "a post to take back"})
	id := dig(posted, "receipt", "id").(string)
	if _, failure := callTool(t, s, theirs, "", "withdraw_message", map[string]any{"message_id": id}); !strings.Contains(failure, "not_author") {
		t.Fatalf("another identity withdrew it: %q", failure)
	}
	got := mustTool(t, s, mine, "", "withdraw_message", map[string]any{"message_id": id[:12]})
	if dig(got, "data", "reason") != board.WithdrawnReason {
		t.Fatalf("withdraw_message: %v", got)
	}
	if _, failure := callTool(t, s, "/mcp", "", "withdraw_message", map[string]any{"message_id": id}); failure == "" {
		t.Fatal("withdraw_message ran without an identity")
	}
	var read struct {
		Messages []board.Message `json:"messages"`
	}
	w := makeRequest(s, "GET", "/e/"+id+"?format=json", "", "")
	if json.Unmarshal(w.Body.Bytes(), &read) != nil || len(read.Messages) != 1 || read.Messages[0].HiddenBy != "author" || read.Messages[0].Reason != board.WithdrawnReason {
		t.Fatalf("/e/ID after withdraw: %d %s", w.Code, w.Body.String())
	}

	post := mustTool(t, s, mine, "", "post_message", map[string]any{"room": "apps", "text": "a visible post"})
	visible := dig(post, "receipt", "id").(string)
	record, err := store.Execute(ctx, signService(appKey, board.Command{Operation: "post", Room: "apps", Kind: "app-state", Text: `{"pinned":"` + visible + `"}`, RequestID: "record-1"}), "198.51.100.8")
	if err != nil {
		t.Fatal(err)
	}
	ids := func(path string) string {
		t.Helper()
		var page struct {
			Messages []board.Message `json:"messages"`
		}
		w := makeRequest(s, "GET", path, "", "")
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &page) != nil {
			t.Fatalf("GET %s: %d %s", path, w.Code, w.Body.String())
		}
		var out []string
		for _, m := range page.Messages {
			if !m.Hidden {
				out = append(out, m.ID)
			}
		}
		return strings.Join(out, ",")
	}
	if got := ids("/api/messages?room=apps&sort=new"); got != visible {
		t.Fatalf("default read: %s", got)
	}
	if got := ids("/api/messages?room=apps&records=only"); got != record.Receipt.ID {
		t.Fatalf("records=only: %s (record %s, visible %s)", got, record.Receipt.ID, visible)
	}
	if got := ids("/api/messages?room=apps&records=include"); got != record.Receipt.ID+","+visible {
		t.Fatalf("records=include: %s", got)
	}
	if w := makeRequest(s, "GET", "/api/messages?room=apps&records=all", "", ""); w.Code != 400 {
		t.Fatalf("records=all: %d", w.Code)
	}
	if w := makeRequest(s, "GET", "/api/updates?records=only", "", ""); w.Code != 400 {
		t.Fatalf("updates records=only: %d", w.Code)
	}
	if w := makeRequest(s, "GET", "/api/updates?records=include", "", ""); w.Code != 200 {
		t.Fatalf("updates records=include: %d %s", w.Code, w.Body.String())
	}
	listed := mustTool(t, s, "/mcp", "", "read_messages", map[string]any{"room": "apps", "records": "only"})
	if msgs, _ := listed["messages"].([]any); len(msgs) != 1 || dig(msgs[0], "id") != record.Receipt.ID {
		t.Fatalf("read_messages records only: %v", listed)
	}
}
