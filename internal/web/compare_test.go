package web

import (
	"encoding/json"
	"html"
	"regexp"
	"slices"
	"strings"
	"testing"

	publicdocs "swarmmemo/docs"
	"swarmmemo/internal/board"
)

// The comparison pages answer the searches agents make when they weigh
// SwarmMemo against another project: each is dated, cites the other
// project's own pages, carries its title, description, canonical and
// FAQPage JSON-LD, is in the sitemap and the Docs hub, and links the hub,
// which links every one of them. A link to a page of SwarmMemo's resolves on
// a deployment with every service on.
func TestComparePages(t *testing.T) {
	sitemap := strings.Join(IndexedNavPaths(t.Context(), nil, board.Features{}), " ")
	_, hub := toolPage(t, everyService, "/compare")
	ld := regexp.MustCompile(`(?s)<script type="application/ld\+json">(.*?)</script>`)
	href := regexp.MustCompile(`href="(/[^"#]*)`)
	for _, c := range publicdocs.Comparisons {
		code, body := toolPage(t, nil, c.Path)
		if code != 200 {
			t.Fatalf("%s without services: %d", c.Path, code)
		}
		text := html.UnescapeString(body)
		for _, want := range []string{"<title>" + c.Title + " · SwarmMemo</title>", `<meta name="description" content="` + c.Description + `">`,
			`<link rel="canonical" href="https://swarmmemo.com` + c.Path + `">`, "Checked 2026-10-21"} {
			if !strings.Contains(text, want) {
				t.Errorf("%s lacks %q", c.Path, want)
			}
		}
		if n := len([]rune(c.Title)); n > 58 {
			t.Errorf("%s: title is %d characters", c.Path, n)
		}
		if n := len([]rune(c.Description)); n > 155 {
			t.Errorf("%s: description is %d characters", c.Path, n)
		}
		var data struct {
			Graph []struct {
				Type       string            `json:"@type"`
				MainEntity []json.RawMessage `json:"mainEntity"`
			} `json:"@graph"`
		}
		m := ld.FindStringSubmatch(body)
		if m == nil || json.Unmarshal([]byte(m[1]), &data) != nil || len(data.Graph) == 0 || data.Graph[0].Type != "FAQPage" || len(data.Graph[0].MainEntity) < 2 {
			t.Errorf("%s: no FAQPage JSON-LD", c.Path)
		}
		if !strings.Contains(" "+sitemap+" ", " "+c.Path+" ") {
			t.Errorf("the sitemap misses %s", c.Path)
		}
		if c.Path != "/compare" && (!strings.Contains(hub, `href="`+c.Path+`"`) || !strings.Contains(body, `href="/compare"`)) {
			t.Errorf("%s and the hub do not link each other", c.Path)
		}
		if md, ok := publicdocs.ReadPath(c.Path + ".md"); !ok || !strings.HasPrefix(string(md), "# ") {
			t.Errorf("%s.md is not served", c.Path)
		}
		_, full := toolPage(t, everyService, c.Path)
		article := full[strings.Index(full, "<article"):strings.Index(full, "</article>")]
		for _, l := range href.FindAllStringSubmatch(article, -1) {
			if strings.HasPrefix(l[1], "/r/") || strings.HasPrefix(l[1], "/api/") || slices.Contains([]string{"/llms.txt", "/protocol.md", "/mcp"}, l[1]) {
				continue // a room's data, or a document the API serves (internal/httpapi checks those)
			}
			if code, _ := toolPage(t, everyService, strings.SplitN(l[1], "?", 2)[0]); code != 200 {
				t.Errorf("%s links %s, which answers %d", c.Path, l[1], code)
			}
		}
	}
}

// The search pages say what is free in plain words: the job pages, the
// comparison pages and the /for pages keep the daily limit's mechanics
// (credits, the allowance, signed commands) out of their copy, and no page
// links a write or receive URL.
func TestSearchPagesSpeakPlainly(t *testing.T) {
	var paths []string
	paths = append(paths, publicdocs.JobPaths()...)
	paths = append(paths, publicdocs.ComparePaths()...)
	paths = append(paths, FrameworkPaths()...)
	paths = append(paths, PlatformPaths()...)
	paths = append(paths, "/tools/screen")
	mechanics := regexp.MustCompile(`(?i)\bcredits\b|\ballowance\b|service\.call|signed commands?\b`)
	tag := regexp.MustCompile(`(?s)<script.*?</script>|<[^>]+>`)
	for _, path := range paths {
		code, body := toolPage(t, everyService, path)
		if code != 200 {
			t.Fatalf("%s: %d", path, code)
		}
		main := body[strings.Index(body, "<main"):strings.Index(body, "</main>")]
		if m := mechanics.FindString(html.UnescapeString(tag.ReplaceAllString(main, " "))); m != "" {
			t.Errorf("%s says %q in its copy", path, m)
		}
		if regexp.MustCompile(`href="[^"]*/(call|in|w|w64|c64)/`).MatchString(main) {
			t.Errorf("%s links a write or receive URL", path)
		}
		if !strings.Contains(main, "free") && !strings.Contains(main, "Free") {
			t.Errorf("%s never says what is free", path)
		}
	}
}

// A /for page links a gain's job page while its service runs, and the
// protocol's section while it does not.
func TestForPageGainsFollowServices(t *testing.T) {
	links := func() string {
		var out []string
		for _, g := range servedGains() {
			out = append(out, g.Link)
		}
		return strings.Join(out, " ")
	}
	if l := links(); !strings.Contains(l, "/protocol.md#wake-ups") || !strings.Contains(l, "/protocol.md#receivers") {
		t.Errorf("without services: %s", l)
	}
	SetNavFeatures(board.Features{Services: everyService})
	t.Cleanup(func() { SetNavFeatures(board.Features{}) })
	if l := links(); !strings.Contains(l, "/tools/wakeup/wake-an-ai-agent-on-reply") || !strings.Contains(l, "/tools/receive/email-address-for-ai-agent") {
		t.Errorf("with every service: %s", l)
	}
}

// A /for page answers its questions in its own name, on the page and as
// FAQPage JSON-LD, and lists what the agent gains with a link for each.
func TestForPagesAnswerQuestions(t *testing.T) {
	ld := regexp.MustCompile(`(?s)<script type="application/ld\+json">(.*?)</script>`)
	for _, path := range append(FrameworkPaths(), PlatformPaths()...) {
		_, body := toolPage(t, everyService, path)
		text := html.UnescapeString(body)
		m := ld.FindStringSubmatch(body)
		if m == nil || !strings.Contains(m[1], `"FAQPage"`) {
			t.Errorf("%s: no FAQPage JSON-LD", path)
		}
		if !strings.Contains(text, "<h3>Is it free?</h3>") || !strings.Contains(text, freeAnswer) {
			t.Errorf("%s does not answer whether it is free", path)
		}
		if slices.Contains(FrameworkPaths(), path) {
			for _, g := range servedGains() {
				if !strings.Contains(body, `href="`+g.Link+`"`) {
					t.Errorf("%s does not link %s", path, g.Link)
				}
			}
		}
	}
}
