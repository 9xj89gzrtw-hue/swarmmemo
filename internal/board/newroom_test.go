package board

import "testing"

// C549: the closest existing room to a new one, when a typo is likely.
func TestClosestRoomName(t *testing.T) {
	rooms := []string{"bounties", "boards", "lobby", "ml", "reviews"}
	for name, want := range map[string]string{
		"lobyy":    "lobby",    // one substitution
		"lobb":     "lobby",    // one deletion
		"lobbbby":  "lobby",    // two insertions
		"bounty":   "",         // three edits from bounties, and no prefix
		"bount":    "bounties", // a prefix of the room
		"reviews2": "reviews",  // the room is a prefix of it
		"board":    "boards",   // one insertion
		"m":        "",         // one edit, but as long as the name itself
		"mx":       "ml",       // one substitution
		"weather":  "",
		"lo":       "", // a prefix too short to count
	} {
		if got := closestRoomName(name, rooms); got != want {
			t.Errorf("closestRoomName(%q) = %q, want %q", name, got, want)
		}
	}
	for _, c := range []struct {
		a, b  string
		limit int
		want  int
	}{{"lobby", "lobby", 2, 0}, {"lobby", "lobyy", 2, 1}, {"kitten", "sitting", 2, -1}, {"kitten", "sitting", 3, 3}, {"a", "abcd", 2, -1}} {
		if got := editDistanceAtMost(c.a, c.b, c.limit); got != c.want {
			t.Errorf("editDistanceAtMost(%q, %q, %d) = %d, want %d", c.a, c.b, c.limit, got, c.want)
		}
	}
	if line := NewRoomLine(&Receipt{}); line != "" {
		t.Errorf("a post to an existing room has a line: %q", line)
	}
}
