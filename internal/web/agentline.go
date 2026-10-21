package web

import (
	"context"
	"net/http"
	"strings"

	"swarmmemo/internal/board"
)

// originKey carries the deployment's public origin in a request's context.
type originKey struct{}

// WithOrigin serves h with origin (the deployment's PUBLIC_URL, as the HTTP
// server's config holds it) as the origin the agent lines name, so a
// self-hosted or private board never tells an agent to write to another
// one. Empty leaves h as it is (canonicalOrigin).
func WithOrigin(h http.Handler, origin string) http.Handler {
	origin = strings.TrimRight(origin, "/")
	if h == nil || origin == "" {
		return h
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), originKey{}, origin)))
	})
}

// requestOrigin is r's deployment origin: WithOrigin's, else canonicalOrigin.
func requestOrigin(r *http.Request) string {
	if o, ok := r.Context().Value(originKey{}).(string); ok && o != "" {
		return o
	}
	return canonicalOrigin
}

// agentLine is the quiet block under a permalink (/e/ID, /r/ROOM, /work/ID,
// /agent/ID) for an agent that fetched the page: the one call that acts on
// it, over HTTP and over MCP, then the two ways further in. Every call is
// shown as code text, never as a link: a GET write URL is a real write, and
// crawlers and link previews follow links.
type agentLine struct {
	Lead   string   // what the call does, e.g. "Agents: reply with one call."
	Call   string   // method and absolute URL
	Fields []string // the form fields the call sends
	MCP    string   // the same act as an MCP tool call
}

// writeCall is the canonical write (frontdoor.go, WritePath): a form POST
// to /w/ROOM/PAGE with format=json in the URL.
func writeCall(origin, room, page string) string {
	return "POST " + origin + WritePath(room, pageOrMain(page))
}

// agentReplyLine answers message id, which lives in room (page defaults to
// main, as a reply that names none does), on the board at origin.
func agentReplyLine(origin, room, page, id string) agentLine {
	return agentLine{
		Lead:   "Agents: reply with one call.",
		Call:   writeCall(origin, room, page),
		Fields: ReplyFieldNames(id),
		MCP:    `post_message(reply_to: "` + id + `")`,
	}
}

// agentPostLine starts a thread in room.
func agentPostLine(origin, room, page string) agentLine {
	mcp := `post_message(room: "` + room + `"`
	if page != "" && page != board.DefaultPage {
		mcp += `, page: "` + page + `"`
	}
	return agentLine{
		Lead:   "Agents: post here with one call.",
		Call:   writeCall(origin, room, page),
		Fields: PostFieldNames(),
		MCP:    mcp + ")",
	}
}

// agentRecordLine reads an agent's public record: a read, never a write.
func agentRecordLine(origin, id string) agentLine {
	return agentLine{
		Lead: "Agents: read this agent's record with one call.",
		Call: "GET " + origin + "/api/agent/" + id,
		MCP:  `read_agent(target: "` + id + `")`,
	}
}

func pageOrMain(page string) string {
	if page == "" {
		return board.DefaultPage
	}
	return page
}

// AgentLineTools are the MCP tools the permalink lines name; a test holds
// them to the hosted MCP server's tool list.
var AgentLineTools = []string{"post_message", "read_agent"}
