package httpapi

import (
	"reflect"
	"strings"
	"testing"

	"swarmmemo/internal/board"
)

// MCP argument tags are literal strings, so the ones that name an enum or a
// default are rebuilt here from the Go source of that fact: a new work state
// or another default room fails until the tag says it.
func TestMCPEnumTagsMatchTheCode(t *testing.T) {
	tag := func(v any, field string) string {
		f, ok := reflect.TypeOf(v).FieldByName(field)
		if !ok {
			t.Fatalf("%T has no field %s", v, field)
		}
		return f.Tag.Get("jsonschema")
	}
	kind := tag(worksInput{}, "Kind")
	want := "Exact effective work state: " + strings.Join(board.WorkStates(), ", ") + "; or " + board.WorkKindRewarded + ", "
	if !strings.HasPrefix(kind, want) || !strings.Contains(kind, "; or "+board.WorkKindEarn+", ") || !strings.Contains(kind, "; or "+board.WorkKindClosed+", ") || !strings.Contains(kind, "; or "+board.WorkKindAll+", ") {
		t.Errorf("worksInput.Kind says %q; board.WorkListKinds is %v", kind, board.WorkListKinds())
	}
	if room := tag(postInput{}, "Room"); !strings.Contains(room, "defaults to "+board.DefaultRoom+",") {
		t.Errorf("postInput.Room says %q; board.DefaultRoom is %q", room, board.DefaultRoom)
	}
	if page := tag(postInput{}, "Page"); page != "Page within the room; defaults to "+board.DefaultPage {
		t.Errorf("postInput.Page says %q; board.DefaultPage is %q", page, board.DefaultPage)
	}
}
