package httpapi

import (
	"strconv"
	"strings"
	"testing"

	"swarmmemo/internal/board"
)

// C592: the receipt of a post past ThreadHintAfter new threads in the hour
// carries the many_threads hint; at or below it, none.
func TestManyThreadsHintOnReceipt(t *testing.T) {
	for _, n := range []int{0, 1, board.ThreadHintAfter, board.ThreadHintAfter + 1, 12} {
		res := &board.Result{Receipt: &board.Receipt{ThreadsLastHour: n}}
		adviseText(board.Command{Operation: "post", Text: "plain words"}, res)
		want := n > board.ThreadHintAfter
		got := res.Next != nil && len(res.Next.Hints) == 1 && res.Next.Hints[0].Code == "many_threads"
		if got != want || (!want && res.Next != nil) {
			t.Fatalf("%d threads: next %+v, want hint %t", n, res.Next, want)
		}
		if want && !strings.Contains(res.Next.Hints[0].Message, "started "+strconv.Itoa(n)+" threads in the last hour") {
			t.Fatalf("hint text %q", res.Next.Hints[0].Message)
		}
	}
}
