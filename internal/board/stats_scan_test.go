package board

import (
	"context"
	"testing"
)

// The stats operation counts in one scan of events (C554); each count must
// equal the count it was once its own query for, over imported, simulation,
// anonymous, signed, edited, hidden and private posts.
func TestStatsOneScanMatchesEachCount(t *testing.T) {
	s := openTest(t, Config{})
	curator, a, b := keyFor(95), keyFor(96), keyFor(97)
	run(t, s, signed(curator, Command{Operation: "agent.register", Handle: curatorHandle}))
	run(t, s, signed(curator, Command{Operation: "post", Kind: "imported", Text: "curator summary"}))
	first := run(t, s, signed(a, Command{Operation: "post", Text: "native signed é"})).Receipt.ID
	run(t, s, signed(a, Command{Operation: "post", Text: "native signed, edited", Data: dataJSON(`"supersedes":"` + first + `"`)}))
	run(t, s, Command{Operation: "post", Text: "native anonymous"})
	run(t, s, signed(b, Command{Operation: "post", Room: "coordination-lab", Kind: "simulation", Text: "simulation"}))
	hidden := run(t, s, signed(b, Command{Operation: "post", Text: "hidden"}))
	if err := s.Moderate(testContext, hidden.Receipt.ID, "fixture", true); err != nil {
		t.Fatal(err)
	}
	run(t, s, signed(b, Command{Operation: "room.create", Room: "private", Visibility: "private"}))
	run(t, s, signed(b, Command{Operation: "post", Room: "private", Text: "private"}))
	stats := run(t, s, Command{Operation: "stats"}).Stats
	const from = " FROM events e JOIN rooms r ON r.name=e.room WHERE r.visibility='public' AND e.hidden=0"
	for key, query := range map[string]string{
		"messages":                  "SELECT count(*)" + from,
		"agents":                    "SELECT count(DISTINCT account)" + from + " AND e.public_key<>''",
		"text_bytes":                "SELECT coalesce(sum(length(CAST(e.text AS BLOB))),0)" + from,
		"imported_messages":         "SELECT count(*)" + from + " AND e.kind='imported'",
		"simulation_messages":       "SELECT count(*)" + from + " AND e.kind='simulation'",
		"simulation_posting_agents": "SELECT count(DISTINCT account)" + from + " AND e.kind='simulation' AND e.public_key<>''",
		"native_messages":           "SELECT count(*)" + from + " AND e.kind NOT IN ('imported','simulation')",
		"native_posts":              "SELECT count(*)" + from + " AND e.kind NOT IN ('imported','simulation') AND e.supersedes=''",
		"native_posting_agents":     "SELECT count(DISTINCT account)" + from + " AND e.kind NOT IN ('imported','simulation') AND e.public_key<>''",
		"rooms":                     "SELECT count(*) FROM rooms WHERE visibility='public'",
		"listed_agents":             "SELECT count(*) FROM identities i WHERE i.successor='' AND " + publicAccountSQL("i.account"),
	} {
		var want int64
		if err := s.db.QueryRowContext(context.Background(), query).Scan(&want); err != nil {
			t.Fatal(err)
		}
		if got, ok := stats[key]; !ok || got != want {
			t.Errorf("%s: %d, want %d", key, got, want)
		}
	}
	if stats["messages"] != 5 || stats["native_posts"] != 2 || stats["agents"] != 3 {
		t.Fatalf("fixture: %+v", stats)
	}
}
