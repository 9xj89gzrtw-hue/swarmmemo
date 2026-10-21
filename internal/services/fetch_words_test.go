package services

import (
	"net/url"
	"os"
	"strings"
	"testing"
)

// FetchHTMLKept and FetchHTMLDropped say what the converter does: a page
// with each kind of element keeps and drops exactly what they name.
func TestFetchHTMLWordsMatchTheConverter(t *testing.T) {
	base, _ := url.Parse("https://example.com/")
	doc := `<html><head><title>T</title><style>.s{}</style><script>var s</script></head><body>
<nav>NAVTEXT</nav><aside>SIDETEXT</aside><h1>Heading</h1><p>Para <a href="/x">LINKTEXT</a></p><ul><li>Item</li></ul><pre><code>CODETEXT</code></pre>
<form>FORMTEXT <input name="q"><button>BUTTONTEXT</button><select><option>MENUTEXT</option></select></form><footer>FOOTTEXT</footer></body></html>`
	got := htmlToText(doc, base).Text
	for word, want := range map[string]bool{
		"# Heading": true, "Item": true, "CODETEXT": true, "[LINKTEXT](https://example.com/x)": true, "FORMTEXT": true,
		"NAVTEXT": false, "SIDETEXT": false, "FOOTTEXT": false, "BUTTONTEXT": false, "MENUTEXT": false, "var s": false, ".s{}": false,
	} {
		if strings.Contains(got, word) != want {
			t.Errorf("%q kept = %v, want %v:\n%s", word, !want, want, got)
		}
	}
	for _, w := range []string{"headings", "lists", "code blocks", "links", "a form's text"} {
		if !strings.Contains(FetchHTMLKept, w) {
			t.Errorf("FetchHTMLKept misses %q", w)
		}
	}
	for _, w := range []string{"scripts", "styles", "navigation", "footers", "sidebars", "buttons", "menus"} {
		if !strings.Contains(FetchHTMLDropped, w) {
			t.Errorf("FetchHTMLDropped misses %q", w)
		}
	}
}

// The fetch guide says the same words.
func TestFetchGuideSaysTheConverterWords(t *testing.T) {
	raw, err := os.ReadFile("../../docs/TOOLS_FETCH.md")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(strings.Fields(string(raw)), " "), FetchHTMLKept+"; "+FetchHTMLDropped) {
		t.Error("docs/TOOLS_FETCH.md does not say FetchHTMLKept; FetchHTMLDropped")
	}
}
