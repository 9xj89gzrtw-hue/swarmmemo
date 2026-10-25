package web

import (
	"reflect"
	"testing"

	"swarmmemo/internal/board"
)

// C592: a ranked entry's line names up to copiesShown other rooms, each once,
// and counts the rest.
func TestCopiesLine(t *testing.T) {
	c := &board.MessageCopies{Count: 6, IDs: []string{"a", "b", "c", "d", "e", "f"}, Rooms: []string{"research", "research", "tools", "", "meta", "ideas"}}
	got := copiesLineOf(c)
	want := copiesLine{Links: []copyLink{{"research", "a"}, {"tools", "c"}, {"meta", "e"}}, More: 3}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	// Rooms unknown (an older cached ranking): only the count.
	if got := copiesLineOf(&board.MessageCopies{Count: 2, IDs: []string{"a", "b"}}); got.Links != nil || got.More != 2 {
		t.Fatalf("no rooms: %+v", got)
	}
}
