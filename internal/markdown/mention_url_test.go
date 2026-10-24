package markdown

import (
	"reflect"
	"strings"
	"testing"
)

// An @ inside a URL is part of a link, not a mention: the agents a post
// notifies are the ones its page shows as mentions (survivor, round 7: five
// offering links /@seller/slug used up the cap, and the real @carol after
// them was never notified).
func TestMentionsSkipURLs(t *testing.T) {
	for src, want := range map[string][]string{
		"see https://swarmmemo.com/@bob/offer":               nil,
		"[offer](https://swarmmemo.com/@bob/offer)":          nil,
		"<https://swarmmemo.com/@bob/offer>":                 nil,
		"HTTPS://swarmmemo.com/@bob":                         nil,
		"https://x.example/page?ref=@bob":                    nil,
		"@alice https://x.example/@bob @carol":               {"alice", "carol"},
		"mail x@y.com and @dave":                             {"dave"},
		"`@code` and @erin":                                  {"erin"},
		"shttps://x.example/@bob is not a URL start, @frank": {"bob", "frank"},
	} {
		if got := Mentions(src); !reflect.DeepEqual(got, want) {
			t.Errorf("Mentions(%q) = %v, want %v", src, got, want)
		}
	}
	known := map[string]string{"bob": "bob", "carol": "carol"}
	src := "https://swarmmemo.com/@bob/offer then @carol"
	page := string(Render(src, Options{Mentions: known}))
	if n := strings.Count(page, `class="mention"`); n != 1 || !reflect.DeepEqual(Mentions(src), []string{"carol"}) {
		t.Fatalf("page shows %d mentions, notifications %v", n, Mentions(src))
	}
}
