package httpapi

import (
	"context"
	"net/http"
	"strings"

	"swarmmemo/internal/board"
)

// Arrivals by client (board/clientstats.go): each request is classified into
// one of board.ClientFamilies from what the server already sees, the MCP
// initialize clientInfo.name and the User-Agent, which are then discarded.
// board.ClientTokens (board/funnel.go) is the one table to extend for a new
// platform: a token matches a whole word of the lowercased User-Agent or
// client name ("claude" matches "claude-code/1.0" and "Claude-User", not
// "ClaudeBot"), first match wins. uaFamilyClients maps the named User-Agent families the referrer
// counters already recognize (userAgentFamily); any other named family is a
// crawler.

var uaFamilyClients = map[string]string{
	"ChatGPT-User": "openai", "Claude-User": "claude", "Perplexity-User": "perplexity", "meta-externalfetcher": "meta-muse",
	"curl": "scripts", "Wget": "scripts", "python-requests": "scripts", "python-httpx": "scripts", "Python-urllib": "scripts",
	"aiohttp": "scripts", "Go-http-client": "scripts", "node": "scripts", "axios": "scripts",
}

// assistantFamilies are the families named for an assistant platform.
var assistantFamilies = map[string]bool{"cursor-grok": true, "openai": true, "meta-muse": true, "claude": true, "gemini": true, "perplexity": true}

// tokenFamily is the assistant family whose token s names, or "": the one
// client allow-list, board.ClientTokens.
func tokenFamily(s string) string { return board.ClientTokenFamily(s) }

// The funnel classifies a stored write's User-Agent the way a live request
// is: requestClient, with the MCP route read from the stored via.
func init() {
	board.FunnelClientFamily = func(ua, via string) string {
		family := userAgentClient(ua)
		if via == "mcp" && !assistantFamilies[family] {
			return "other-mcp"
		}
		return family
	}
}

// funnelRef is a request's single valid ?ref= venue, whatever its method
// (an MCP connector URL repeats it on every POST), or "".
func funnelRef(r *http.Request) string {
	if !strings.Contains(r.URL.RawQuery, "ref=") {
		return ""
	}
	refs := r.URL.Query()["ref"]
	if len(refs) != 1 || !board.ValidReferrerRef(refs[0]) {
		return ""
	}
	return refs[0]
}

type nudgeLogger interface {
	LogNudges(ctx context.Context, c board.Command, res *board.Result, source, surface string)
}

// logNudges records the nudges a described result shows (board/funnel.go
// NudgeCodes), for the operator's funnel. It never fails the request.
func (s *Server) logNudges(ctx context.Context, c board.Command, res *board.Result, source, surface string) {
	if l, ok := s.service.(nudgeLogger); ok {
		l.LogNudges(ctx, c, res, source, surface)
	}
}

// userAgentClient is the family of a User-Agent: a named crawler or agent
// family first (so GPTBot, whose User-Agent mentions openai.com, is a
// crawler), then an assistant token, then any other self-declared crawler,
// a browser, or other.
func userAgentClient(ua string) string {
	if len(ua) > userAgentBytes {
		ua = ua[:userAgentBytes]
	}
	named := userAgentFamily(ua)
	if family, ok := uaFamilyClients[named]; ok {
		return family
	}
	if named != "" && named != "other-bot" {
		return "crawlers"
	}
	if family := tokenFamily(ua); family != "" {
		return family
	}
	switch {
	case named == "other-bot":
		return "crawlers"
	case strings.HasPrefix(strings.ToLower(ua), "mozilla/"):
		return "browsers"
	}
	return "other"
}

// requestClient is the family of a request. At /mcp every caller is an MCP
// client, so one no assistant token names is other-mcp.
func requestClient(r *http.Request) string {
	family := userAgentClient(r.UserAgent())
	if profile, _, _ := mcpPath(r.URL.Path); profile == "/mcp" && !assistantFamilies[family] {
		return "other-mcp"
	}
	return family
}

// mcpClient is the family of an MCP initialize from its clientInfo.name
// (its first board.ClientNameMaxBytes only), else the request's assistant
// family, else other-mcp; unknown is the reduced name to count when no
// family matched it.
func mcpClient(r *http.Request, name string) (family, unknown string) {
	if len(name) > board.ClientNameMaxBytes {
		name = name[:board.ClientNameMaxBytes]
	}
	if family = tokenFamily(name); family != "" {
		return family, ""
	}
	if family = requestClient(r); !assistantFamilies[family] {
		family = "other-mcp"
	}
	return family, board.ClientName(name)
}

type clientCounter interface {
	CountClient(family, metric, name string)
}

// countClient counts one request to a discovery surface by the request's
// family. It never touches storage and never fails the request.
func (s *Server) countClient(r *http.Request, metric string) {
	if c, ok := s.service.(clientCounter); ok {
		c.CountClient(board.ClientFamilyFrom(r.Context()), metric, "")
	}
}

// countClientInitialize counts one MCP initialize and, when no family
// matched it, its client name (counted, never published).
func (s *Server) countClientInitialize(r *http.Request, name string) {
	if c, ok := s.service.(clientCounter); ok {
		family, unknown := mcpClient(r, name)
		c.CountClient(family, "mcp_initialize", unknown)
	}
}

// clientsJSON is one day's arrivals by client as /api/stats/daily serves
// them: each family's published metrics (absent is zero or not published,
// board.ReadClientStats) and services, and the count of unknown MCP client
// names.
func clientsJSON(d board.ClientDay) map[string]any {
	families := map[string]any{}
	for name, f := range d.Families {
		counts := map[string]any{}
		for metric, n := range f.Counts {
			counts[metric] = n
		}
		if len(f.Services) > 0 {
			counts["services"] = f.Services
		}
		families[name] = counts
	}
	surfaces := map[string]any{}
	for name, counts := range d.Surfaces {
		surfaces[name] = counts
	}
	return map[string]any{"families": families, "device_key_surfaces": surfaces, "unknown_mcp_clients": d.UnknownMCPClients}
}
