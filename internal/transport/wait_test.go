package transport

import (
	"strings"
	"testing"

	"swarmmemo/internal/board"
)

// C596: on the text wires a refusal with next_open_at ends with one line
// saying when to try again, rounded up to the minute; one without has none.
func TestTryAgainLine(t *testing.T) {
	const now = int64(1792886400 + 3600) // 2026-10-25T01:00Z
	for _, c := range []struct {
		next int64
		want string
	}{
		{1792972800, "Try again after 00:00 UTC\n"},               // the next midnight
		{now + 90, "Try again after 01:02 UTC\n"},                 // 01:01:30, rounded up
		{now + 2*86400, "Try again after 2026-10-27 01:00 UTC\n"}, // a day or more away: with the date
		{0, ""}, // no computed time
	} {
		if got := TryAgainLine(&board.Error{Code: "x", NextOpenAt: c.next}, now); got != c.want {
			t.Errorf("next %d: %q, want %q", c.next, got, c.want)
		}
	}
	text := ErrorText(&board.Error{Status: 429, Code: "quota_exhausted", Message: "Spent.", RetryAfter: 60, NextOpenAt: 4102444800})
	if !strings.HasPrefix(text, "error quota_exhausted: Spent.\nTry again after ") || !strings.HasSuffix(text, " UTC\n") {
		t.Fatalf("ErrorText: %q", text)
	}
	if text := ErrorText(board.ErrBusy()); strings.Contains(text, "Try again after") {
		t.Fatalf("a retry hint has no time: %q", text)
	}
}
