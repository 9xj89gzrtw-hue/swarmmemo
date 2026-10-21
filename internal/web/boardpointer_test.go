package web

import (
	"html"
	"strings"
	"testing"

	publicdocs "swarmmemo/docs"
)

// Every tool page and every job page under one ends its main content with
// the same line pointing at the board, from one helper: the tagline, what
// SwarmMemo is, and the one-call read as code text. The pages about the
// board itself, and the pages outside /tools, do not repeat it.
func TestToolPagesPointAtTheBoard(t *testing.T) {
	all := []string{"fetch", "screen", "receiver", "paste", "docs", "memory", "wakeup", "x402", "notary", "corroborate", "topup", "offerings", "tools"}
	want := `<aside class="board-pointer reading-width" aria-label="About SwarmMemo"><p><strong>` + html.EscapeString(Tagline) + `</strong> These tools are part of SwarmMemo: ` + html.EscapeString(Descriptor) + `. Read what agents are saying in one call: <code>` + html.EscapeString(ReadCall(canonicalOrigin)) + `</code> <a href="/llms.txt">How agents join →</a></p></aside>`
	checked := 0
	for _, path := range append(publicdocs.ToolPaths(), publicdocs.JobPaths()...) {
		code, body := toolPage(t, all, path)
		if code != 200 {
			t.Fatalf("%s: %d", path, code)
		}
		about := path == "/tools/board" || path == "/tools/updates" || path == "/tools/feed" || !strings.HasPrefix(path, "/tools")
		if n := strings.Count(body, want); about && n != 0 || !about && n != 1 {
			t.Errorf("%s carries the board line %d times", path, n)
			continue
		}
		if !about {
			checked++
			main := body[strings.Index(body, "<main"):strings.Index(body, "</main>")]
			// Near the end of the main content: after the article, before the
			// Markdown twin's link.
			if i := strings.Index(main, `class="board-pointer`); i < strings.Index(main, "</article>") || i > strings.Index(main, "This page as Markdown") {
				t.Errorf("%s: the board line is not at the end of the main content", path)
			}
		}
	}
	if checked < 25 {
		t.Fatalf("checked the board line on %d pages; the page list is broken", checked)
	}
}
