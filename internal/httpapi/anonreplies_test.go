package httpapi

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"swarmmemo/internal/board"
)

// C72: every transport that returns a post response says the same thing when
// replies wait on the same network's earlier anonymous posts today: JSON
// POST, the GET write URL (JSON and text) and MCP. Another network and a
// signed post hear nothing.
func TestAnonymousRepliesWaitingOnEveryWire(t *testing.T) {
	store, err := board.Open(filepath.Join(t.TempDir(), "board.sqlite"), board.Config{ServiceID: "swarmmemo.com", Features: board.Features{AnonPrefix: true}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	if _, err = store.SetAllowanceParams(t.Context(), board.PostingParamsNamespace, []byte(`{"anonymous_top_level_per_hour":1000}`), "test", 0); err != nil {
		t.Fatal(err)
	}
	s := New(store, nil, Config{PublicURL: "https://swarmmemo.com", ServiceID: "swarmmemo.com", Version: "test"})
	send := func(addr, method, path, body string, mcp bool) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, "https://swarmmemo.com"+path, strings.NewReader(body))
		r.RemoteAddr = addr + ":4000"
		if body != "" {
			r.Header.Set("Content-Type", "application/json")
		}
		if mcp {
			r.Header.Set("Accept", "application/json, text/event-stream")
		}
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("%s %s: %d %s", method, path, w.Code, w.Body.String())
		}
		return w
	}
	result := func(w *httptest.ResponseRecorder) board.Result {
		t.Helper()
		var res board.Result
		if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil || res.Receipt == nil {
			t.Fatalf("not a receipt: %s %v", w.Body.String(), err)
		}
		return res
	}
	first := result(send("198.51.100.7", "POST", "/v1/command", `{"operation":"post","text":"a question"}`, false))
	if first.Next == nil || first.Next.RepliesWaiting != "" {
		t.Fatalf("a first post: %+v", first.Next)
	}
	// Each receipt tells of a reply once, so every wire below follows a fresh
	// answer from another network.
	// Each answer differs: the same reply twice is refused (C599).
	answers := 0
	answer := func() {
		t.Helper()
		answers++
		result(send("203.0.113.9", "POST", "/v1/command", `{"operation":"post","text":"answer `+strconv.Itoa(answers)+`","reply_to":"`+first.Receipt.ID+`"}`, false))
	}
	answer()
	want := "1 reply waits on your earlier unsigned posts today: https://swarmmemo.com/e/" + first.Receipt.ID
	// The first post from the network carried the sign_for_replies tip; the
	// same code waits a week before it is shown to that network again.
	if first.Next.Nudge == nil || first.Next.Nudge.Code != "sign_for_replies" {
		t.Fatalf("a first post's tip: %+v", first.Next)
	}

	if got := result(send("198.51.100.8", "POST", "/v1/command", `{"operation":"post","text":"again"}`, false)).Next; got == nil || got.RepliesWaiting != want || got.Nudge != nil {
		t.Fatalf("JSON POST: %+v", got)
	}
	answer()
	if got := result(send("198.51.100.9", "GET", "/w/lobby/main?text=again+by+get&format=json", "", false)).Next; got == nil || got.RepliesWaiting != want {
		t.Fatalf("GET write URL: %+v", got)
	}
	answer()
	text := send("198.51.100.10", "GET", "/w/lobby/main?text=again+as+text", "", false).Body.String()
	// ok, replies_url and its note (C462), then the sentence.
	if lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n"); len(lines) != 4 || lines[3] != want {
		t.Fatalf("text receipt: %q", text)
	}
	answer()
	w := send("198.51.100.11", "POST", "/mcp", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"post_message","arguments":{"text":"again by mcp"}}}`, true)
	var rpc struct {
		Result struct {
			StructuredContent board.Result `json:"structuredContent"`
		} `json:"result"`
	}
	if err = json.Unmarshal(w.Body.Bytes(), &rpc); err != nil || rpc.Result.StructuredContent.Next == nil || rpc.Result.StructuredContent.Next.RepliesWaiting != want {
		t.Fatalf("MCP: %s %v", w.Body.String(), err)
	}
	// Told once: the next post from the same pseudonym hears nothing more.
	if got := result(send("198.51.100.12", "POST", "/v1/command", `{"operation":"post","text":"told already"}`, false)).Next; got != nil && got.RepliesWaiting != "" {
		t.Fatalf("a repeated nudge: %+v", got)
	}
	// The replier's network asked nothing that was answered.
	if got := result(send("203.0.113.10", "POST", "/v1/command", `{"operation":"post","text":"mine"}`, false)).Next; got != nil && got.RepliesWaiting != "" {
		t.Fatalf("another network: %+v", got)
	}
	if text = send("192.0.2.1", "GET", "/w/lobby/main?text=elsewhere", "", false).Body.String(); strings.Contains(text, "waiting") {
		t.Fatalf("another network, text: %q", text)
	}
}

// The text wires that skip describeReceipt print the same sentence with
// board-relative links.
func TestWriteTextRepliesWaitingWithoutDescribe(t *testing.T) {
	var b strings.Builder
	WriteText(&b, board.Result{Receipt: &board.Receipt{ID: "m", Hash: "h", RepliesWaiting: &board.RepliesWaiting{Replies: 2, Posts: []string{"p1"}}}})
	if !strings.Contains(b.String(), "\n2 replies wait on your earlier unsigned posts today: /e/p1\n") {
		t.Fatalf("%q", b.String())
	}
}
