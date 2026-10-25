package httpapi

import (
	"context"
	"crypto/tls"
	"net/http"
	"regexp"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"swarmmemo/internal/board"
)

// Request signals (C160): what the board records, operator-only, about each
// accepted write that arrived over HTTP (board/signals.go). The address is
// the peer (s.peer: X-Forwarded-For only from the loopback proxy), hashed by
// the board; nothing here is stored unless the request is an accepted write.

// bridgeSenderHeader is the sending domain a verified email bridge reports
// (deploy/cloudflare-email). It is read only after the bridge's secret checked
// out; anyone else's is ignored.
const bridgeSenderHeader = "X-SwarmMemo-Bridge-Sender-Domain"

var senderDomain = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)

// withSignals records the request's headers for the board. C452: the whole
// header set, the TCP peer, the trusted proxy's X-Forwarded-For chain and the
// HTTP and TLS versions go only into the sealed raw record of an accepted
// write (board/rawsignals.go), which redacts credential-bearing headers.
func (s *Server) withSignals(r *http.Request) *http.Request {
	var hints []string
	for _, h := range []string{"Sec-CH-UA", "Sec-CH-UA-Platform", "Sec-CH-UA-Mobile"} {
		if v := r.Header.Get(h); v != "" {
			hints = append(hints, h+"="+v)
		}
	}
	sig := board.RequestSignals{
		UserAgent:      r.Header.Get("User-Agent"),
		Referer:        r.Header.Get("Referer"),
		AcceptLanguage: r.Header.Get("Accept-Language"),
		ClientHints:    strings.Join(hints, "; "),
		Headers:        r.Header,
		RemoteAddr:     r.RemoteAddr,
		Proto:          r.Proto,
	}
	if r.TLS != nil {
		sig.TLS = tls.VersionName(r.TLS.Version)
	}
	if s.trustedProxy(r) {
		sig.ForwardedFor = strings.Join(r.Header.Values("X-Forwarded-For"), ", ")
	}
	return r.WithContext(board.WithRequestSignals(r.Context(), sig))
}

// mcpClientSignals adds an MCP call's clientInfo (its request _meta, else the
// session's initialize) to the request signals, for the raw record.
func mcpClientSignals() mcp.Middleware {
	return func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			if call, ok := req.(*mcp.CallToolRequest); ok {
				if info := call.ClientInfo(); info != nil {
					sig := board.RequestSignalsFrom(ctx)
					sig.MCPClient = &board.MCPClientInfo{Name: info.Name, Title: info.Title, Version: info.Version}
					ctx = board.WithRequestSignals(ctx, sig)
				}
			}
			return next(ctx, method, req)
		}
	}
}

// withBridgeSender adds a verified email bridge's sending domain.
func withBridgeSender(r *http.Request, via string) *http.Request {
	if via != "email" {
		return r
	}
	domain := strings.ToLower(strings.TrimSpace(r.Header.Get(bridgeSenderHeader)))
	if len(domain) > 253 || !senderDomain.MatchString(domain) {
		return r
	}
	sig := board.RequestSignalsFrom(r.Context())
	sig.Origin = "email:" + domain
	return r.WithContext(board.WithRequestSignals(r.Context(), sig))
}
