package httpapi

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"swarmmemo/internal/board"
)

// find_work and /api/works take since (C540): the first page's data.since,
// sent back, answers unchanged with no rows; since with cursor is refused;
// the tool says how often to poll, from the one constant.
func TestPollSinceOverMCPAndHTTP(t *testing.T) {
	_, s := hostedServer(t)
	first := mustTool(t, s, "/mcp", "", "find_work", map[string]any{"kind": "open"})
	since, _ := dig(first, "data", "since").(string)
	if since == "" || dig(first, "data", "next_poll_seconds") != float64(board.PollSeconds) {
		t.Fatalf("find_work first page %v", first)
	}
	same := mustTool(t, s, "/mcp", "", "find_work", map[string]any{"kind": "open", "since": since})
	if dig(same, "data", "unchanged") != true || len(dig(same, "data", "works").([]any)) != 0 {
		t.Fatalf("find_work since %v", same)
	}
	if _, failure := callTool(t, s, "/mcp", "", "find_work", map[string]any{"since": since, "cursor": "x"}); !strings.HasPrefix(failure, "400 invalid_request") {
		t.Fatalf("since with cursor: %q", failure)
	}
	// A damaged since is the full list, marked reset.
	other := mustTool(t, s, "/mcp", "", "find_work", map[string]any{"kind": "open", "since": "nope"})
	if dig(other, "data", "since_reset") != true || dig(other, "data", "unchanged") != nil {
		t.Fatalf("find_work other since %v", other)
	}

	w := get(s, "/api/works?kind=open", "application/json")
	var page struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil || page.Data["since"] == nil {
		t.Fatalf("/api/works %d %s", w.Code, w.Body.String())
	}
	w = get(s, "/api/works?kind=open&since="+url.QueryEscape(page.Data["since"].(string)), "application/json")
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil || page.Data["unchanged"] != true {
		t.Fatalf("/api/works since %d %s", w.Code, w.Body.String())
	}
	if w = get(s, "/api/works?since=a&cursor=b", "application/json"); w.Code != 400 {
		t.Fatalf("/api/works since with cursor %d", w.Code)
	}

	// Offerings are off here: their tools' descriptions are read from the specs.
	for _, d := range []string{mcpToolDescription(t, s, "find_work"), mcpToolDescription(t, s, "read_thread"), offeringReadTools[0].Desc, offeringProviderTools[1].Desc} {
		if !strings.Contains(d, "at most every "+board.PollEvery) {
			t.Fatalf("description without the poll interval: %q", d)
		}
	}
}

// mcpToolDescription is a tool's description as tools/list gives it.
func mcpToolDescription(t *testing.T, s *Server, name string) string {
	t.Helper()
	out := mcpRequest(t, s, "/mcp", "", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	tools, _ := dig(out, "result", "tools").([]any)
	for _, tool := range tools {
		if m := tool.(map[string]any); m["name"] == name {
			return m["description"].(string)
		}
	}
	t.Fatalf("no tool %s", name)
	return ""
}
