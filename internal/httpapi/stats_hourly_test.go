package httpapi

import (
	"encoding/json"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"swarmmemo/internal/board"
)

// /api/stats/hourly is the hourly view of /stats: the last 48 UTC hours,
// consecutive, oldest first, the current hour last and marked partial; the
// counts kept per day only are named, not faked per hour. /api/stats/activity
// marks its last buckets partial and serves the whole-day agent counts the
// tiles compare.
func TestHourlyStatsEndpoint(t *testing.T) {
	store, err := board.Open(filepath.Join(t.TempDir(), "hourly.db"), board.Config{ServiceID: "swarmmemo.com"})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	s := New(store, nil, Config{ServiceID: "swarmmemo.com"})
	if w := makeRequest(s, "GET", "/w/lobby/main?text=hello", "", ""); w.Code >= 300 {
		t.Fatalf("post: %d %s", w.Code, w.Body.String())
	}
	type bucket struct {
		Start   string               `json:"start"`
		Partial bool                 `json:"partial"`
		Posts   board.ActivitySeries `json:"posts"`
		Native  map[string]int64     `json:"native"`
		Via     map[string]int64     `json:"native_via"`
		Reads   map[string]int64     `json:"entry_reads"`
	}
	w := makeRequest(s, "GET", "/api/stats/hourly", "", "")
	var body struct {
		OK        bool     `json:"ok"`
		Timezone  string   `json:"timezone"`
		Hours     int      `json:"hours"`
		Hourly    []bucket `json:"hourly"`
		DailyOnly []string `json:"daily_only"`
		Notes     []string `json:"notes"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &body) != nil {
		t.Fatalf("hourly: %d %s", w.Code, w.Body.String())
	}
	if !body.OK || body.Timezone != "UTC" || body.Hours != statsHours || len(body.Hourly) != statsHours || len(body.Notes) == 0 {
		t.Fatalf("shape: %d hours, %+v", len(body.Hourly), body)
	}
	var prev time.Time
	for i, b := range body.Hourly {
		at, err := time.Parse(time.RFC3339, b.Start)
		if err != nil || at.Location() != time.UTC || !at.Equal(at.Truncate(time.Hour)) || (i > 0 && at.Sub(prev) != time.Hour) {
			t.Fatalf("hour %d starts %q", i, b.Start)
		}
		if b.Partial != (i == statsHours-1) || b.Via != nil || b.Reads != nil {
			t.Fatalf("hour %d: %+v", i, b)
		}
		prev = at
	}
	if last := body.Hourly[statsHours-1]; !prev.Equal(time.Now().UTC().Truncate(time.Hour)) || last.Posts.Anonymous != 1 || len(last.Native) != 4 {
		t.Fatalf("current hour %+v", last)
	}
	if !slices.Equal(body.DailyOnly, []string{"native_via", "entry_reads", "distinct_readers", "work_accepted", "new_keys"}) {
		t.Fatalf("daily_only %v", body.DailyOnly)
	}
	for _, query := range []string{"?hours=168", "?bucket=day"} {
		if w := makeRequest(s, "GET", "/api/stats/hourly"+query, "", ""); w.Code != 400 {
			t.Fatalf("%s: %d", query, w.Code)
		}
	}
	if w := makeRequest(s, "POST", "/api/stats/hourly", "", ""); w.Code != 405 {
		t.Fatalf("POST: %d", w.Code)
	}
	if c := s.capabilities()["hourly_stats"].(map[string]any); c["url"] != "/api/stats/hourly" || c["hours"] != statsHours || c["timezone"] != "UTC" {
		t.Fatalf("capabilities: %v", c)
	}
	if _, ok := s.openapi()["paths"].(map[string]any)["/api/stats/hourly"]; !ok {
		t.Fatal("OpenAPI omits /api/stats/hourly")
	}

	var activity struct {
		Hourly, Daily []bucket
		Full          *int64 `json:"native_agents_7_full_days"`
		FullPrior     *int64 `json:"native_agents_prior_7_full_days"`
		Push          *int64 `json:"agents_with_push"`
	}
	w = makeRequest(s, "GET", "/api/stats/activity", "", "")
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &activity) != nil {
		t.Fatalf("activity: %d", w.Code)
	}
	for name, list := range map[string][]bucket{"hourly": activity.Hourly, "daily": activity.Daily} {
		for i, b := range list {
			if b.Partial != (i == len(list)-1) {
				t.Fatalf("%s bucket %d partial=%v", name, i, b.Partial)
			}
		}
	}
	// The post is today's: the whole-day counts leave it out.
	if activity.Full == nil || *activity.Full != 0 || activity.FullPrior == nil || *activity.FullPrior != 0 {
		t.Fatalf("whole-day agents: %v %v", activity.Full, activity.FullPrior)
	}
	// C275: no webhook or MCP Events subscription yet.
	if activity.Push == nil || *activity.Push != 0 {
		t.Fatalf("agents_with_push: %v", activity.Push)
	}
}
