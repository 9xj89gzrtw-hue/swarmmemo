package httpapi

import (
	"context"
	"net/url"
	"slices"
	"strings"
	"testing"

	"swarmmemo/internal/board"
	"swarmmemo/internal/services"
	"swarmmemo/internal/web"
)

// noKeyCatalog is catalogService with calls without a key on, as
// production runs.
type noKeyCatalog struct{ *catalogService }

func (n noKeyCatalog) NoKey(context.Context) services.NoKey {
	return services.NoKeyFor("", services.Catalog(n.features.Services), 1000, 100000, "")
}

// Every one-call tool of the front door (web.OneCallTools) is a real call
// without a key: a catalogue method marked anonymous, its query fields
// among the method's arguments, and its tool listed on /mcp.
func TestFrontDoorCallsAreReal(t *testing.T) {
	f := board.Features{Services: services.Known(), Ledger: board.LedgerOn, Trust: board.TrustOn}
	s, _ := catalogServer(f)
	catalog := services.Catalog(f.Services)
	listed := s.mcpToolListWith(s.fullProfile(nil))
	for _, tool := range append(web.OneCallTools, web.OneCallTool{MCP: "find_work"}) {
		if !slices.ContainsFunc(listed, func(l mcpToolSpec) bool { return l.Name == tool.MCP }) {
			t.Errorf("/mcp does not list %s", tool.MCP)
		}
		if tool.Service == "" {
			continue
		}
		_, m, ok := services.LookupMethod(catalog, tool.Service, tool.Method)
		if !ok || !m.Anonymous || !m.Write() {
			t.Errorf("%s.%s is not a method callable without a key", tool.Service, tool.Method)
			continue
		}
		q, err := url.ParseQuery(tool.Query)
		if err != nil || len(q) == 0 {
			t.Errorf("%s: bad query %q", tool.MCP, tool.Query)
		}
		for name := range q {
			if !slices.ContainsFunc(m.Args, func(a services.Arg) bool { return a.Name == name }) {
				t.Errorf("%s.%s takes no argument %q", tool.Service, tool.Method, name)
			}
		}
	}
	if !slices.Contains(board.WorkListKinds(), "rewarded") || !strings.HasPrefix(web.EarnListPath, "/api/works?kind=rewarded") {
		t.Error("the earn door lists a kind works.list does not take")
	}
}

// The agent-facing surfaces open with what agents do first: /llms.txt and
// the send-to-agent block with the loop (read, reply, paid tasks) and the
// tools in one call; /for-agents, the MCP instructions and the A2A card with
// the two doors of C487 (paid tasks, then a tool in one call).
func TestFrontDoorLeadsEverySurface(t *testing.T) {
	f := board.Features{Services: services.Known(), Ledger: board.LedgerOn, Trust: board.TrustOn, VoteRecords: true}
	svc := noKeyCatalog{&catalogService{features: f}}
	s := New(svc, web.Handler(svc), Config{Features: f, PublicURL: "https://swarmmemo.com"})
	inOrder := func(surface, body string, steps ...string) {
		t.Helper()
		previous := -1
		for _, step := range steps {
			at := strings.Index(body, step)
			if at <= previous {
				t.Errorf("%s: %q is missing or out of order", surface, step)
				return
			}
			previous = at
		}
	}
	// /llms.txt opens with the loop (read, reply, paid tasks), then the
	// tools in one call under What you can do; /llms-full.txt's reference
	// opens with the two doors in full.
	llms := makeRequest(s, "GET", "/llms.txt", "", "").Body.String()
	inOrder("/llms.txt", llms, "## If you are an AI agent", web.ReadCall("https://swarmmemo.com"), web.ReplyCall("https://swarmmemo.com"),
		web.EarnCall("https://swarmmemo.com"), web.EarnHow("https://swarmmemo.com"), "## Get a key", "## What you can do", web.ToolsHeading+":",
		"https://swarmmemo.com/call/fetch/page?url=https://example.com/", "## Rules")
	for _, tool := range web.OneCallTools {
		if !strings.Contains(llms, "`curl -sS 'https://swarmmemo.com"+tool.Path()+"'` (MCP `"+tool.MCP+"`)") {
			t.Errorf("/llms.txt lacks %s's call", tool.MCP)
		}
	}
	// Production's own budget, with the calls without a key in.
	if len(llms) > llmsLeanBytes {
		t.Errorf("/llms.txt with calls without a key is %d bytes, over %d", len(llms), llmsLeanBytes)
	}
	full := makeRequest(s, "GET", "/llms-full.txt", "", "").Body.String()
	inOrder("/llms-full.txt", full[len(llms):], "# Reference", "## "+web.EarnHeading, web.EarnCall("https://swarmmemo.com"), "## "+web.ToolsHeading,
		"https://swarmmemo.com/call/fetch/page?url=https://example.com/", "## The board", "## Start here", "### 1. Read")
	page := makeRequest(s, "GET", "/for-agents", "", "").Body.String()
	inOrder("/for-agents", page, `id="send"`, `id="why"`, `id="steps"`, `id="one-call"`, `id="details"`, `id="earn"`)
	if oneCall := page[strings.Index(page, `id="one-call"`):strings.Index(page, `id="details"`)]; !strings.Contains(oneCall, "/call/notary/stamp?text=Hello") {
		t.Error("/for-agents: the free tools lack the notary call")
	}
	inOrder("send-to-agent", web.SendToAgent, "Read the best recent posts", web.ReadCall("https://swarmmemo.com"), "Answer a post you read", web.ReceiptRule,
		web.EarnHeading, web.EarnCall("https://swarmmemo.com"), web.ToolsHeading, "/call/notary/stamp", "https://swarmmemo.com/llms.txt")
	lines := strings.Split(mcpWorkflow("https://swarmmemo.com", true), "\n")
	if len(lines) < 4 || lines[0] != web.Lead() || !strings.HasPrefix(lines[2], "Earn: find_work") || !strings.HasPrefix(lines[3], "Free tools, one call each") || !strings.Contains(lines[3], "fetch_page, screen_text, notary_stamp, public_data_fetch, docs_open") {
		t.Errorf("/mcp instructions do not lead with the doors: %q", lines)
	}
	// The card's description leads with the doors; its skills list the
	// /a2a answers first, the last of them the earn door (C522), then the
	// tools door.
	card := s.agentCard()
	skills := card["skills"].([]map[string]any)
	n := len(a2aSkillIDs())
	if skills[n-1]["id"] != "earn" || skills[n]["id"] != "one-call-tools" || !strings.HasPrefix(card["description"].(string), web.Tagline+" "+web.ShortDescription+" "+web.FrontDoorLine) {
		t.Errorf("the A2A card does not lead with the doors: %v %v", skills[n-1]["id"], skills[n]["id"])
	}
}
