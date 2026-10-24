package httpapi

// The size of the core profile's tools/list (C134b): what a client takes
// into its context when it attaches every tool. The framework pages state it
// (web.SetCoreToolsList), measured from the very server /mcp/core serves, so
// the number follows the tools instead of drifting.

import (
	"context"
	"encoding/json"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// CoreToolsList measures /mcp/core's tools/list: the bytes of its JSON-RPC
// answer and how many tools it lists. It lists over an in-memory session, as
// an anonymous client would.
func (s *Server) CoreToolsList(ctx context.Context) (size, tools int, err error) {
	all, err := listedMCPTools(ctx, s.mcpCore)
	if err != nil {
		return 0, 0, err
	}
	raw, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "result": &mcp.ListToolsResult{Tools: all}})
	if err != nil {
		return 0, 0, err
	}
	return len(raw), len(all), nil
}
