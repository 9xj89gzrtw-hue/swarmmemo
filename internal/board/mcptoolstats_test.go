package board

import (
	"strings"
	"testing"
	"time"
)

// MCP tool stats take only the fixed key shapes, sum over a window, and
// keep sketches only MCPToolSketchDays.
func TestMCPToolStats(t *testing.T) {
	s := openTest(t, Config{})
	day0 := time.Unix(testTime, 0).UTC()
	s.now = func() time.Time { return day0 }
	sketch := func(ids ...string) *ReaderSketch {
		h := &ReaderSketch{}
		for _, id := range ids {
			h.Add(id)
		}
		return h
	}
	// An invalid key never fails the batch: it is skipped and counted, and
	// the batch's valid keys are still written.
	for _, bad := range []map[string]int64{
		{"mcp:read_feed:claude:views": 1},       // unknown metric
		{"web:read_feed:claude:calls": 1},       // unknown profile
		{"mcp:read_feed:203.0.113.1:calls": 1},  // not a family
		{"mcp:Read-Feed:claude:calls": 1},       // not a tool name
		{"mcp:read.feed:claude:calls": 1},       // not a tool name
		{"mcp:read_feed:claude:calls:extra": 1}, // extra part
		{"mcp:read_feed:claude:calls": -1},      // negative
	} {
		bad["core:list_rooms:claude:calls"] = 1
		if err := s.AddMCPToolStats(testContext, day0.Format("2006-01-02"), bad, nil); err != nil {
			t.Fatalf("refused the batch of %v: %v", bad, err)
		}
	}
	if err := s.AddMCPToolStats(testContext, day0.Format("2006-01-02"), nil, map[string]*ReaderSketch{"mcp:curl/8.5.0": sketch("a"), "core:list_rooms": nil, "core:" + strings.Repeat("x", 49): sketch("z")}); err != nil {
		t.Fatal(err)
	}
	if err := s.AddMCPToolStats(testContext, "2026-13-01", map[string]int64{"core:list_rooms:claude:calls": 1}, nil); err == nil {
		t.Fatal("accepted an invalid day")
	}
	var skipped, rooms int64
	if err := s.db.QueryRow("SELECT value FROM counters WHERE scope=?", mcpToolSkippedPrefix+day0.Format("2006-01-02")).Scan(&skipped); err != nil || skipped != 10 {
		t.Fatalf("skipped %d %v, want 10", skipped, err)
	}
	if err := s.db.QueryRow("SELECT value FROM counters WHERE scope=?", mcpToolScopePrefix+day0.Format("2006-01-02")+":core:list_rooms:claude:calls").Scan(&rooms); err != nil || rooms != 7 {
		t.Fatalf("valid keys beside invalid ones: %d %v, want 7", rooms, err)
	}
	if w, err := s.MCPToolStats(testContext, day0, 1); err != nil || w.Skipped != 10 || len(w.Tools) != 1 || w.Tools[0].Tool != "list_rooms" || w.Tools[0].Calls != 7 {
		t.Fatalf("window with skipped keys: %+v %v", w, err)
	}
	var stored int
	if err := s.db.QueryRow("SELECT count(*) FROM counters WHERE scope LIKE 'mcp_tool%' AND (scope LIKE '%203.0.113%' OR scope LIKE '%curl%' OR scope LIKE '%Read-Feed%' OR scope LIKE '%views%' OR scope LIKE 'mcp_tool:%:web:%')").Scan(&stored); err != nil || stored != 0 {
		t.Fatalf("an invalid key reached storage: %d %v", stored, err)
	}
	if _, err := s.db.Exec("DELETE FROM counters WHERE scope LIKE 'mcp_tool%'"); err != nil {
		t.Fatal(err)
	}
	add := func(at time.Time, counts map[string]int64, sketches map[string]*ReaderSketch) {
		t.Helper()
		s.now = func() time.Time { return at }
		if err := s.AddMCPToolStats(testContext, at.Format("2006-01-02"), counts, sketches); err != nil {
			t.Fatal(err)
		}
	}
	add(day0, map[string]int64{"mcp:read_feed:claude:calls": 3, "mcp:read_feed:claude:errors": 1, "core:home:openai:calls": 2},
		map[string]*ReaderSketch{"mcp:read_feed": sketch("a", "b"), "mcp:any": sketch("a", "b"), "core:home": sketch("c")})
	add(day0, map[string]int64{"mcp:read_feed:other-mcp:calls": 1}, map[string]*ReaderSketch{"mcp:read_feed": sketch("b", "d")})
	day1 := day0.AddDate(0, 0, 1)
	add(day1, map[string]int64{"mcp:read_feed:claude:calls": 1}, map[string]*ReaderSketch{"mcp:read_feed": sketch("a")})

	w, err := s.MCPToolStats(testContext, day1, 7)
	if err != nil {
		t.Fatal(err)
	}
	if len(w.Tools) != 2 || w.Tools[0].Tool != "read_feed" || w.Tools[0].Calls != 5 || w.Tools[0].Errors != 1 || w.Tools[0].CallerDays != 4 ||
		w.Tools[0].Families["claude"] != 4 || w.Tools[0].Families["other-mcp"] != 1 {
		t.Fatalf("window: %+v", w.Tools)
	}
	if len(w.Profiles) != 2 || w.Profiles[0].Profile != "mcp" || w.Profiles[0].Calls != 5 || w.Profiles[0].CallerDays != 2 || w.Profiles[1].Profile != "core" || w.Profiles[1].Calls != 2 {
		t.Fatalf("profiles: %+v", w.Profiles)
	}
	if one, _ := s.MCPToolStats(testContext, day1, 1); len(one.Tools) != 1 || one.Tools[0].Calls != 1 {
		t.Fatalf("one day: %+v", one.Tools)
	}
	// Two days on, day0's sketches are gone; its estimates stay.
	add(day0.AddDate(0, 0, MCPToolSketchDays), nil, map[string]*ReaderSketch{"mcp:home": sketch("x")})
	var n int
	if err := s.db.QueryRow("SELECT count(*) FROM meta WHERE key LIKE ?", mcpToolSketchPrefix+day0.Format("2006-01-02")+"%").Scan(&n); err != nil || n != 0 {
		t.Fatalf("old sketches kept: %d %v", n, err)
	}
	if w, _ = s.MCPToolStats(testContext, day1, 7); w.Tools[0].CallerDays != 4 {
		t.Fatalf("estimates lost: %+v", w.Tools[0])
	}
	if _, err := s.MCPToolStats(testContext, day1, 0); err == nil {
		t.Fatal("a zero-day window")
	}
}
