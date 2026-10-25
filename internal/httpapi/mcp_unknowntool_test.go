package httpapi

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestClosestTool(t *testing.T) {
	names := []string{"read_messages", "post_message", "read_thread", "read_feed", "read_updates", "read_agent", "find_agents", "screen_text", "notary_get", "notary_stamp", "whoami"}
	for guess, want := range map[string]string{
		"get_messages": "read_messages", // same word, same kind of verb
		"send_message": "post_message",
		"get_thread":   "read_thread",
		"Get-Updates":  "read_updates",
		"post":         "post_message", // a bare first word
		"screen":       "screen_text",
		"notary":       "notary_get",
		"teleport":     "",
		"":             "",
	} {
		if got := closestTool(guess, names); got != want {
			t.Errorf("closestTool(%q) = %q, want %q", guess, got, want)
		}
	}
}

// An unknown name keeps the SDK's invalid-params error and its opening
// words, and gains the closest tool and where to look; a known one passes.
func TestUnknownToolHint(t *testing.T) {
	passed := false
	next := func(context.Context, string, mcp.Request) (mcp.Result, error) {
		passed = true
		return &mcp.CallToolResult{}, nil
	}
	call := func(searchable bool, name string) error {
		passed = false
		mw := unknownToolHint(map[string]bool{"read_messages": true, "post_message": true}, searchable)
		_, err := mw(next)(context.Background(), "tools/call", &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: name}})
		return err
	}
	if err := call(true, "read_messages"); err != nil || !passed {
		t.Fatalf("a known tool: err %v passed %v", err, passed)
	}
	var je *jsonrpc.Error
	err := call(true, "get_messages")
	if !errors.As(err, &je) || je.Code != jsonrpc.CodeInvalidParams || passed {
		t.Fatalf("an unknown tool: %v", err)
	}
	if !strings.HasPrefix(je.Message, `unknown tool "get_messages"`) || !strings.Contains(je.Message, "Did you mean read_messages?") || !strings.Contains(je.Message, searchToolsName) {
		t.Fatalf("hint: %q", je.Message)
	}
	if err := call(false, "teleport"); !errors.As(err, &je) || strings.Contains(je.Message, "Did you mean") || strings.Contains(je.Message, searchToolsName) || !strings.Contains(je.Message, "tools/list") {
		t.Fatalf("no match, no search tool: %v", err)
	}
}
