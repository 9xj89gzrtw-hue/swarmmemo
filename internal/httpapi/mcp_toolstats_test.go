package httpapi

import (
	"context"
	"database/sql"
	"fmt"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	_ "modernc.org/sqlite"

	"swarmmemo/internal/board"
	"swarmmemo/internal/web"
)

// Every tools/call on a hosted profile is counted by profile, tool and
// client family, with its errors and distinct callers; an unknown tool
// folds into one bucket; nothing that identifies a caller is stored; the
// counts reach storage only through the batched flush.
func TestMCPToolCallsCounted(t *testing.T) {
	dir := t.TempDir()
	store, err := board.Open(filepath.Join(dir, "board.sqlite"), board.Config{ServiceID: "swarmmemo.com"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	s := New(store, nil, Config{PublicURL: "https://swarmmemo.com", ServiceID: "swarmmemo.com"})
	s.readers.interval = time.Hour // only the explicit flush writes
	call := func(path, addr, ua, body string) {
		t.Helper()
		r := httptest.NewRequest("POST", "https://swarmmemo.com"+path, strings.NewReader(body))
		r.RemoteAddr = addr + ":5555"
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Accept", "application/json, text/event-stream")
		r.Header.Set("User-Agent", ua)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
		}
	}
	tool := func(name, args string) string {
		return `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + name + `","arguments":` + args + `}}`
	}
	// Three callers read the feed on /mcp: two networks, one twice.
	call("/mcp", "203.0.113.10", "curl/8.5.0", tool("read_feed", `{}`))
	call("/mcp", "203.0.113.11", "curl/8.5.0", tool("read_feed", `{}`))
	call("/mcp", "198.51.100.20", "Claude-User/1.0", tool("read_feed", `{}`))
	call("/mcp", "198.51.100.20", "Claude-User/1.0", tool("read_feed", `{}`))
	// A refusal is an error; an unknown tool is "other".
	call("/mcp", "198.51.100.20", "Claude-User/1.0", tool("read_thread", `{"message_id":"nope"}`))
	call("/mcp", "198.51.100.20", "Claude-User/1.0", tool("no_such_tool_"+strings.Repeat("x", 30), `{}`))
	// The other profiles count apart.
	call(mcpProfileCore, "192.0.2.30", "curl/8.5.0", tool("list_rooms", `{}`))
	call(web.AssistantMCPPath, "192.0.2.31", "curl/8.5.0", tool("find_work", `{}`))
	// tools/list and initialize are not tool calls.
	call("/mcp", "192.0.2.32", "curl/8.5.0", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)

	s.FlushReaderCounts()
	w, err := store.MCPToolStats(context.Background(), time.Now(), 7)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]board.MCPToolRow{}
	for _, r := range w.Tools {
		got[r.Profile+":"+r.Tool] = r
	}
	feed := got["mcp:read_feed"]
	if feed.Calls != 4 || feed.Errors != 0 || feed.CallerDays != 2 {
		t.Fatalf("read_feed: %+v", feed)
	}
	if feed.Families["claude"] != 2 || feed.Families["other-mcp"] != 2 {
		t.Fatalf("read_feed families: %v", feed.Families)
	}
	// A refusal is counted under its error code; a failure without one
	// under "other".
	if r := got["mcp:read_thread"]; r.Calls != 1 || r.Errors != 1 || len(r.ErrorCodes) != 1 || r.ErrorCodes[0].Code == board.MCPToolOther || r.ErrorCodes[0].Errors != 1 {
		t.Fatalf("read_thread: %+v", r)
	}
	if r := got["mcp:"+board.MCPToolOther]; r.Calls != 1 || r.Errors != 1 || len(r.ErrorCodes) != 1 || r.ErrorCodes[0].Code != board.MCPToolOther {
		t.Fatalf("unknown tool: %+v (rows %v)", r, got)
	}
	if feed.ErrorCodes != nil {
		t.Fatalf("read_feed codes without errors: %+v", feed.ErrorCodes)
	}
	if got["core:list_rooms"].Calls != 1 || got["assistant:find_work"].Calls != 1 || len(got) != 5 {
		t.Fatalf("rows: %+v", got)
	}
	profiles := map[string]board.MCPToolRow{}
	for _, p := range w.Profiles {
		profiles[p.Profile] = p
	}
	if p := profiles["mcp"]; p.Calls != 6 || p.Errors != 2 || p.CallerDays != 2 || len(p.ErrorCodes) != 2 {
		t.Fatalf("/mcp profile: %+v", p)
	}

	// Stored: only the fixed keys, no address, token or User-Agent.
	db, err := sql.Open("sqlite", filepath.Join(dir, "board.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query("SELECT scope FROM counters WHERE scope LIKE 'mcp_tool%' UNION ALL SELECT key FROM meta WHERE key LIKE 'mcp_tool%'")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			t.Fatal(err)
		}
		n++
		for _, leak := range []string{"203.0.113", "198.51.100", "192.0.2", "curl", "Claude-User", "no_such_tool"} {
			if strings.Contains(k, leak) {
				t.Fatalf("stored key %q carries %q", k, leak)
			}
		}
	}
	if n == 0 {
		t.Fatal("nothing stored")
	}
}

// The counter never writes on a call's path: until the flush, storage holds
// nothing.
func TestMCPToolCountsWaitForTheFlush(t *testing.T) {
	store, s := hostedServer(t)
	s.readers.interval = time.Hour
	s.readers.tools.lastFlush = time.Now()
	mustTool(t, s, "/mcp", "", "list_rooms", map[string]any{})
	w, err := store.MCPToolStats(context.Background(), time.Now(), 1)
	if err != nil || len(w.Tools) != 0 {
		t.Fatalf("before the flush: %+v %v", w, err)
	}
	s.FlushReaderCounts()
	if w, err = store.MCPToolStats(context.Background(), time.Now(), 1); err != nil || len(w.Tools) != 1 || w.Tools[0].Calls != 1 {
		t.Fatalf("after the flush: %+v %v", w, err)
	}
}

// callCounted runs one tools/call of name through the profile's counting
// middleware, as from peer with userAgent and the hosted token.
func callCounted(s *Server, mw mcp.Middleware, ctx context.Context, name string, handler mcp.MethodHandler) {
	if handler == nil {
		handler = func(context.Context, string, mcp.Request) (mcp.Result, error) { return &mcp.CallToolResult{}, nil }
	}
	_, _ = mw(handler)(ctx, "tools/call", &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: name}})
}

// A registered tool name a counts key cannot carry (a hyphen, a dot, past
// 48 bytes) is counted as "other", so the day's flush still writes every
// count: one odd name never fails a batch.
func TestMCPToolOddRegisteredNameFoldsIntoOther(t *testing.T) {
	store, s := hostedServer(t)
	s.readers.interval = time.Hour
	long := strings.Repeat("x", 49)
	mw := s.countMCPTools("mcp", map[string]bool{"read_feed": true, "read-feed": true, "read.feed": true, long: true})
	ctx := context.WithValue(context.Background(), peerContextKey{}, "203.0.113.10")
	for _, name := range []string{"read_feed", "read-feed", "read.feed", long} {
		callCounted(s, mw, ctx, name, nil)
	}
	s.FlushReaderCounts()
	w, err := store.MCPToolStats(context.Background(), time.Now(), 1)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int64{}
	for _, r := range w.Tools {
		got[r.Tool] = r.Calls
	}
	if len(got) != 2 || got["read_feed"] != 1 || got[board.MCPToolOther] != 3 || w.Skipped != 0 {
		t.Fatalf("tools %v, skipped %d", got, w.Skipped)
	}
	c := s.readers.tools
	c.mu.Lock()
	requeued := c.pending[time.Now().UTC().Format("2006-01-02")] != nil
	c.mu.Unlock()
	if requeued {
		t.Fatal("the flush failed and requeued the day")
	}
}

// A distinct caller is a hosted account only once its token resolved on the
// request; any other token is no subject, so made-up tokens from one client
// count as that one client (its network and User-Agent), while one hosted
// identity from two networks, by header and by path, counts once.
func TestMCPToolCallerNeedsResolvedToken(t *testing.T) {
	store, s := hostedServer(t)
	s.readers.interval = time.Hour
	token := newIdentity(t, s, "counted-helper")["token"].(string)
	call := func(addr, ua, path, authorization, name string) {
		t.Helper()
		body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + name + `","arguments":{}}}`
		r := httptest.NewRequest("POST", "https://swarmmemo.com"+path, strings.NewReader(body))
		r.RemoteAddr = addr + ":5555"
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Accept", "application/json, text/event-stream")
		r.Header.Set("User-Agent", ua)
		r.Header.Set("Authorization", authorization)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("%s %s: %d %s", name, authorization, w.Code, w.Body.String())
		}
	}
	// A path token is not checked before the tool runs (a bearer one is, by
	// the OAuth gate), and a public tool never resolves it.
	for i := range 6 {
		call("203.0.113.10", "curl/8.5.0", fmt.Sprintf("/mcp/t/made-up-%d", i), "", "read_feed")
		call("203.0.113.10", "curl/8.5.0", fmt.Sprintf("/mcp/t/%s%032x", board.HostedTokenPrefix, i), "", "read_feed")
	}
	call("198.51.100.20", "Claude-User/1.0", "/mcp", "Bearer "+token, "whoami")
	call("192.0.2.40", "openai-mcp/1.0", "/mcp/t/"+token, "", "whoami")
	s.FlushReaderCounts()
	w, err := store.MCPToolStats(context.Background(), time.Now(), 1)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]board.MCPToolRow{}
	for _, r := range w.Tools {
		got[r.Tool] = r
	}
	if r := got["read_feed"]; r.Calls != 12 || r.CallerDays != 1 {
		t.Fatalf("made-up tokens: %+v", r)
	}
	if r := got["whoami"]; r.Calls != 2 || r.Errors != 0 || r.CallerDays != 1 {
		t.Fatalf("one hosted identity from two networks: %+v", r)
	}
}

// The operator's own local stdio session is not hosted usage: its calls are
// not counted.
func TestMCPToolStdioNotCounted(t *testing.T) {
	store, s := hostedServer(t)
	s.readers.interval = time.Hour
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serverSide, clientSide := mcp.NewInMemoryTransports()
	done := make(chan error, 1)
	go func() { done <- s.RunMCP(ctx, "core", serverSide) }()
	session, err := mcp.NewClient(&mcp.Implementation{Name: "stdio-test", Version: "1"}, nil).Connect(ctx, clientSide, nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "list_rooms", Arguments: map[string]any{}})
	if err != nil || res.IsError {
		t.Fatalf("list_rooms over stdio: %+v %v", res, err)
	}
	session.Close()
	cancel()
	<-done
	// The same call over HTTP is counted, so the store is not just empty.
	mustTool(t, s, mcpProfileCore, "", "list_rooms", map[string]any{})
	s.FlushReaderCounts()
	w, err := store.MCPToolStats(context.Background(), time.Now(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(w.Tools) != 1 || w.Tools[0].Tool != "list_rooms" || w.Tools[0].Calls != 1 {
		t.Fatalf("stdio call counted: %+v", w.Tools)
	}
}
