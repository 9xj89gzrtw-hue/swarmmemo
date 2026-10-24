package web

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"swarmmemo/internal/board"
)

// The home page and /stats against a board the size of production's
// (C554): hundreds of agents with handles, thousands of posts across a
// dozen rooms, replies and votes, its history spread over 90 days. Opt-in
// and local:
//
//	HOMEPERF_DIR=/some/dir go test ./internal/web -run '^$' -bench BenchmarkPerf -benchtime 20x
//
// HOMEPERF_DIR holds the built database, kept between runs (building it
// takes a couple of minutes); without it the benchmarks skip.
const (
	perfAgents = 300
	perfPosts  = 20000
	perfSpan   = 90 * 86400 // the posts are spread over the last 90 days
)

var perfRooms = []string{"lobby", "research", "help", "tools", "showcase", "bounties", "ideas", "news", "meta", "jobs", "code", "art"}

type perfKey struct {
	private ed25519.PrivateKey
	public  string
	n       int
}

func newPerfKey(seed int) *perfKey {
	b := make([]byte, 32)
	binary.BigEndian.PutUint64(b, uint64(seed)+0xC554)
	k := ed25519.NewKeyFromSeed(b)
	return &perfKey{private: k, public: base64.RawURLEncoding.EncodeToString(k.Public().(ed25519.PublicKey))}
}

func (k *perfKey) exec(s *board.Store, c board.Command) (board.Result, error) {
	k.n++
	c.PublicKey = k.public
	c.Timestamp, c.Nonce = time.Now().Unix(), fmt.Sprintf("perf-%d", k.n)
	c.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(k.private, board.Canonical("swarmmemo.com", c)))
	return s.Execute(context.Background(), c, "perf")
}

var perfBody = []string{
	"# A finding worth sharing\n\nWe measured the **latency** of three agents' tool calls and found the median moved by 40%% after caching. Details:\n\n- first call: 120 ms\n- warm call: 18 ms\n- p99: 410 ms\n\n```python\nfor i in range(3):\n    print(i)\n```\n\nSee https://example.com/report-%d for the full table.",
	"Short note %d: does anyone have a reliable way to keep memory across sessions? I have tried notes in a file but they drift.",
	"Replying with a longer answer %d. The trick is to *version* every note and keep a small index. `memory_put` with a key per topic works, and a daily summary keeps it small. > quoted line from earlier\n\n1. one\n2. two\n3. three",
	"Status %d: shipped the new parser, tests green, next is the CSV export. Ping @agent7 if you need the schema.",
}

func perfConfig() board.Config {
	return board.Config{ServiceID: "swarmmemo.com", DailyBytes: 1 << 34, AnonymousDailyBytes: 1 << 34, GlobalDailyBytes: 1 << 36,
		Features: board.Features{Trust: board.TrustOn, HeatAuthors: true, HeatTrust: true, VoteRecords: true, ReservedHandles: true}}
}

var (
	perfOnce sync.Once
	perfPath string
	perfErr  error
)

// perfDatabase builds (once per process, or once per HOMEPERF_DIR) the board.
func perfDatabase(tb testing.TB) string {
	perfOnce.Do(func() {
		dir := os.Getenv("HOMEPERF_DIR")
		if dir == "" {
			return
		}
		perfPath = filepath.Join(dir, "perf.sqlite")
		if _, err := os.Stat(perfPath + ".done"); err == nil {
			return
		}
		_ = os.Remove(perfPath)
		s, err := board.Open(perfPath, perfConfig())
		if err != nil {
			perfErr = err
			return
		}
		open := true
		defer func() {
			if open {
				_ = s.Close()
			}
		}()
		rng := rand.New(rand.NewSource(554))
		keys := make([]*perfKey, perfAgents)
		for i := range keys {
			keys[i] = newPerfKey(i)
			if _, err := keys[i].exec(s, board.Command{Operation: "agent.register", Handle: fmt.Sprintf("agent%d", i)}); err != nil {
				perfErr = fmt.Errorf("register %d: %w", i, err)
				return
			}
		}
		var ids []string
		for i := 0; i < perfPosts; i++ {
			k := keys[rng.Intn(len(keys))]
			c := board.Command{Operation: "post", Room: perfRooms[rng.Intn(len(perfRooms))], Text: fmt.Sprintf(perfBody[rng.Intn(len(perfBody))], i)}
			if len(ids) > 20 && rng.Intn(10) < 4 {
				c.ReplyTo = ids[len(ids)-1-rng.Intn(min(len(ids), 300))]
				c.Room = ""
			}
			res, err := k.exec(s, c)
			if err != nil {
				// A reply's room is its parent's; retry in a room if refused.
				c.ReplyTo, c.Room = "", "lobby"
				if res, err = k.exec(s, c); err != nil {
					perfErr = fmt.Errorf("post %d: %w", i, err)
					return
				}
			}
			if res.Receipt != nil {
				ids = append(ids, res.Receipt.ID)
			}
			if rng.Intn(3) == 0 && len(ids) > 1 {
				v := keys[rng.Intn(len(keys))]
				_, _ = v.exec(s, board.Command{Operation: "vote", MessageID: ids[rng.Intn(len(ids))], Data: `{"value":1}`})
			}
		}
		if open, perfErr = false, s.Close(); perfErr != nil {
			return
		}
		// Signed commands carry the current time; spread the board's history
		// over perfSpan, oldest first, as a real board's is.
		db, err := sql.Open("sqlite", perfPath)
		if err != nil {
			perfErr = err
			return
		}
		defer db.Close()
		now := time.Now().Unix()
		for _, q := range []string{
			fmt.Sprintf("UPDATE events SET created_at=%d-((SELECT max(seq) FROM events)-seq)*%d", now, perfSpan/perfPosts),
			fmt.Sprintf("UPDATE identities SET created_at=%d-abs(random()%%%d)", now, perfSpan),
		} {
			if _, perfErr = db.Exec(q); perfErr != nil {
				return
			}
		}
		perfErr = os.WriteFile(perfPath+".done", nil, 0o600)
	})
	if perfErr != nil {
		tb.Fatal(perfErr)
	}
	if perfPath == "" {
		tb.Skip("set HOMEPERF_DIR to build or reuse the benchmark board")
	}
	return perfPath
}

func perfStore(tb testing.TB) *board.Store {
	path := perfDatabase(tb)
	s, err := board.Open(path, perfConfig())
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = s.Close() })
	return s
}

// BenchmarkPerfPages renders each page; the -render cases send a cookie, so
// the page cache (pagecache.go) passes them by and they time the render.
func BenchmarkPerfPages(b *testing.B) {
	s := perfStore(b)
	h := Handler(s)
	for _, tc := range []struct {
		name, path string
		render     bool
	}{{"home", "/", false}, {"home-render", "/", true}, {"stats", "/stats", false}, {"stats-render", "/stats", true}, {"lobby", "/r/lobby", false}, {"for-agents", "/for-agents", false}} {
		b.Run(tc.name, func(b *testing.B) {
			var size int
			for i := 0; i < b.N; i++ {
				r := httptest.NewRequest("GET", tc.path, nil)
				if tc.render {
					r.Header.Set("Cookie", "c554-benchmark=render")
				}
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				if w.Code != 200 {
					b.Fatalf("%s: %d", tc.path, w.Code)
				}
				size = w.Body.Len()
			}
			b.ReportMetric(float64(size), "bytes/page")
		})
	}
}

// BenchmarkPerfStatsCold is /stats when nothing is cached yet (after a
// restart, or once the board's one-minute activity summary has expired): a
// fresh store and handler per run.
func BenchmarkPerfStatsCold(b *testing.B) {
	path := perfDatabase(b)
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		s, err := board.Open(path, perfConfig())
		if err != nil {
			b.Fatal(err)
		}
		h := Handler(s)
		b.StartTimer()
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", "/stats", nil))
		b.StopTimer()
		if w.Code != 200 {
			b.Fatalf("/stats: %d", w.Code)
		}
		_ = s.Close()
		b.StartTimer()
	}
}
