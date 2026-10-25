package httpapi

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// unknownToolHint answers a tools/call naming a tool this profile does not
// have, which the SDK answers with a bare `unknown tool "x"`: the same
// invalid-params error, its message followed by the closest tool of the
// profile (when one shares a word with the name) and where to look next, so
// a caller that guessed a name ("get_messages", "search") has its next call.
// Roughly 60 callers a week sent such names and left on the bare error.
// known is every tool the profile registers; searchable says whether the
// profile offers search_swarmmemo_tools.
func unknownToolHint(known map[string]bool, searchable bool) mcp.Middleware {
	names := make([]string, 0, len(known))
	for name, ok := range known {
		if ok {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			call, ok := req.(*mcp.CallToolRequest)
			if method != "tools/call" || !ok || call.Params == nil || known[call.Params.Name] {
				return next(ctx, method, req)
			}
			msg := fmt.Sprintf("unknown tool %q", truncateName(call.Params.Name))
			if best := closestTool(call.Params.Name, names); best != "" {
				msg += fmt.Sprintf(". Did you mean %s?", best)
			}
			if searchable {
				msg += " " + searchToolsName + " finds a tool by what it does; tools/list shows this connection's tools."
			} else {
				msg += " tools/list shows this connection's tools."
			}
			return nil, &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: msg}
		}
	}
}

// toolNameFiller are words that say nothing about what a tool does.
var toolNameFiller = map[string]bool{"set": true, "do": true, "the": true, "swarmmemo": true, "tool": true, "my": true}

// toolVerbs groups the verbs a guessed name starts with by what they do, so
// a tie between tools sharing a word goes to the one that does the same
// kind of thing: get_messages is read_messages, not post_message.
var toolVerbs = map[string]string{
	"get": "read", "read": "read", "fetch": "read", "list": "read", "show": "read", "view": "read", "find": "read", "search": "read", "query": "read", "lookup": "read",
	"post": "write", "send": "write", "create": "write", "add": "write", "write": "write", "put": "write", "publish": "write", "reply": "write", "submit": "write",
}

// closestTool is the name in names sharing the most meaningful words with
// name (split on _ - . and space, case-folded, a trailing s dropped), a
// same-kind leading verb breaking ties, then the shorter name; "" when none
// shares a word and a bare word is no tool's first word.
func closestTool(name string, names []string) string {
	want, wantVerb := toolWords(name), toolVerb(name)
	best, bestScore := "", 0
	for _, n := range names {
		shared := 0
		for w := range toolWords(n) {
			if want[w] {
				shared++
			}
		}
		if shared == 0 {
			continue
		}
		score := 2 * shared
		if wantVerb != "" && toolVerb(n) == wantVerb {
			score++
		}
		if score > bestScore || (score == bestScore && len(n) < len(best)) {
			best, bestScore = n, score
		}
	}
	if best == "" {
		// A bare word ("post", "screen") is the first word of the tool it
		// means: the shortest such tool.
		if parts := splitToolName(name); len(parts) == 1 {
			for _, n := range names {
				if p := splitToolName(n); len(p) > 1 && p[0] == parts[0] && (best == "" || len(n) < len(best)) {
					best = n
				}
			}
		}
	}
	return best
}

func splitToolName(name string) []string {
	return strings.FieldsFunc(strings.ToLower(name), func(r rune) bool { return r == '_' || r == '-' || r == '.' || r == ' ' })
}

func toolWords(name string) map[string]bool {
	words := map[string]bool{}
	for _, w := range splitToolName(name) {
		w = strings.TrimSuffix(w, "s")
		if w != "" && !toolNameFiller[w] && toolVerbs[w] == "" {
			words[w] = true
		}
	}
	return words
}

// toolVerb is the kind of a name's leading verb, "" when it has none.
func toolVerb(name string) string {
	if parts := splitToolName(name); len(parts) > 0 {
		return toolVerbs[parts[0]]
	}
	return ""
}
