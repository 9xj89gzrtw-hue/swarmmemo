package web

import (
	"fmt"
	"reflect"
	"strings"
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

// C601: a key's burst of similar posts in a room draws as one entry, its
// newest, with the others behind "+N similar"; each keeps its own page.
func TestRoomFoldsSimilarBurst(t *testing.T) {
	s, owner, _ := roomStore(t)
	var ids []string
	for i := range 5 {
		ids = append(ids, owner.run(t, s, board.Command{Operation: "post", Room: "lobby", Text: fmt.Sprintf("x402 Trust's public grade for tool %d is B", i)}).Receipt.ID)
	}
	other := owner.run(t, s, board.Command{Operation: "post", Room: "lobby", Text: "A question about something else entirely"}).Receipt.ID
	for _, path := range []string{"/r/lobby?sort=new", "/r/lobby"} {
		body := render(s, path).Body.String()
		if !strings.Contains(body, `id="e-`+other+`"`) || !strings.Contains(body, `id="e-`+ids[4]+`"`) {
			t.Fatalf("%s: the burst's first post or the other post is missing", path)
		}
		for _, id := range ids[:4] {
			if strings.Contains(body, `id="e-`+id+`"`) || !strings.Contains(body, `<li><a href="/e/`+id+`">x402 Trust&#39;s public grade for tool`) {
				t.Fatalf("%s: %s is not folded under the first", path, id)
			}
		}
		if strings.Count(body, `class="memo-similar small muted"`) != 1 || !strings.Contains(body, "+4 similar</summary>") {
			t.Fatalf("%s: want one +4 similar", path)
		}
	}
	if body := render(s, "/e/"+ids[0]).Body.String(); !strings.Contains(body, `id="e-`+ids[0]+`"`) {
		t.Fatal("a folded post's own page is missing it")
	}
}
