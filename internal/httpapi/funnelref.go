package httpapi

import (
	"crypto/rand"
	"crypto/sha256"
	"net/http"
	"sync"
	"time"
)

// A link that says who sent an agent carries ?ref=VENUE (board.ValidReferrerRef)
// on the page the agent lands on: /, /for-agents, /llms.txt. The agent's
// first signed write comes later, on /v1/command, without it. firstContactRef
// carries the venue across: a landing GET's ref is remembered for its network
// for refMemoTTL, in memory only (a salted hash of the IPv4 address or
// IPv6 /64, never stored), and a later request from that network that names
// no ref of its own takes it. The board keeps it only on the account's first day, first ref winning
// (board/funnel_store.go), so an existing account is never re-credited.
//
// MCP requests take only the ref on their own URL (a connector repeats it on
// every call): many assistants share one MCP egress, so a network's ref
// would credit strangers.

const (
	refMemoTTL = 6 * time.Hour
	refMemoMax = 8192
)

type refSeen struct {
	ref string
	at  time.Time
}

// refMemo is the network → first landing ref table. The zero value is ready.
type refMemo struct {
	mu   sync.Mutex
	salt [16]byte
	m    map[[16]byte]refSeen
	now  func() time.Time // tests
}

// key is the memo's key of peer's network: the address for IPv4, its /64
// for IPv6 (limiterKey), since one IPv6 host may send its landing GET and
// its first write from two addresses of its /64 (privacy addresses).
func (m *refMemo) key(peer string) [16]byte {
	var k [16]byte
	h := sha256.Sum256(append(m.salt[:], limiterKey(peer)...))
	copy(k[:], h[:])
	return k
}

func (m *refMemo) clock() time.Time {
	if m.now != nil {
		return m.now()
	}
	return time.Now()
}

// remember notes ref for peer unless a live one is there: the first wins.
func (m *refMemo) remember(peer, ref string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.clock()
	if m.m == nil {
		_, _ = rand.Read(m.salt[:])
		m.m = map[[16]byte]refSeen{}
	}
	k := m.key(peer)
	if old, ok := m.m[k]; ok && now.Sub(old.at) < refMemoTTL {
		return
	}
	if len(m.m) >= refMemoMax {
		for k2, v := range m.m {
			if now.Sub(v.at) >= refMemoTTL {
				delete(m.m, k2)
			}
		}
		if len(m.m) >= refMemoMax {
			return
		}
	}
	m.m[k] = refSeen{ref: ref, at: now}
}

// lookup is peer's remembered ref, or "".
func (m *refMemo) lookup(peer string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.m == nil {
		return ""
	}
	v, ok := m.m[m.key(peer)]
	if !ok || m.clock().Sub(v.at) >= refMemoTTL {
		return ""
	}
	return v.ref
}

// firstContactRef is the funnel venue of a request: its own ?ref=, else
// (not on MCP) the ref its network's landing page carried.
func (s *Server) firstContactRef(r *http.Request, isMCP bool) string {
	if ref := funnelRef(r); ref != "" {
		if refKey(r) != "" {
			s.refs.remember(s.peer(r), ref)
		}
		return ref
	}
	if isMCP {
		return ""
	}
	return s.refs.lookup(s.peer(r))
}
