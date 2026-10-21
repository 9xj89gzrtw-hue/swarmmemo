package web

//go:generate env SWARMMEMO_WRITE_GENERATED=1 go test -run TestLexiconStaticFiles -count=1 .

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
)

// The static files that restate the positioning (READMEs, the MCP Registry
// record, the plugin and its skills, the integrations, the dataset card)
// take it from the glossary's positioning block, and the READMEs and the
// protocol take the canonical calls from frontdoor.go: the text between
// <!-- BEGIN LEXICON: key --> and <!-- END LEXICON -->, a JSON field or a
// skill's YAML description is generated, never typed. This test fails when
// one drifts; `go generate ./internal/web` rewrites them.

// lexiconValue is the text a marker key stands for: a positioning key, or
// one of the composites the files use.
func lexiconValue(key string) (string, bool) {
	p := Positioning()
	switch key {
	case "category":
		return p.Category, true
	case "descriptor":
		return p.Descriptor, true
	case "summary":
		return p.Summary, true
	case "free":
		return p.Free, true
	case "limit":
		return p.Limit, true
	case "tools":
		return p.Tools, true
	case "headline": // a README's first lines: the category in bold, then the summary
		return "**" + p.Category + "**\n" + p.Summary, true
	case "lead":
		return Lead(), true
	case "intro":
		return Intro(), true
	// The canonical calls (frontdoor.go), fenced.
	case "call.post":
		return "```sh\n" + PostCall(canonicalOrigin) + "\n```", true
	case "calls.first":
		return "```sh\n" + ReadCall(canonicalOrigin) + "\n" + PostCall(canonicalOrigin) + "\n```", true
	// The connect-URL rule (platforms.go).
	case "connect.rule":
		return ConnectRule(canonicalOrigin), true
	}
	for _, prop := range p.Props {
		if key == "prop."+prop.Key {
			return prop.Text(), true
		}
	}
	return "", false
}

// lexiconMarkerFiles carry marker blocks, at least this many each.
var lexiconMarkerFiles = map[string]int{
	"README.md":                                       2,
	"release/PUBLIC_README.md":                        2,
	"docs/PROTOCOL.md":                                2,
	"clients/mcp/README.md":                           1,
	"plugins/swarmmemo/README.md":                     1,
	"plugins/swarmmemo/skills/use-swarmmemo/SKILL.md": 1,
	"scripts/dataset_card.md":                         2,
	"integrations/crewai/README.md":                   1,
	"integrations/langchain/README.md":                1,
	"integrations/agno/README.md":                     1,
}

// lexiconField is one generated JSON string field or YAML description:
// key's value, then, when tail is set, the field's own text from tail on.
type lexiconField struct {
	file, field, key, tail string
	yaml                   bool
}

var lexiconFields = []lexiconField{
	{file: "ops/mcp_registry/server.json", field: "description", key: "category"},
	{file: "plugins/swarmmemo/plugin.json", field: "shortDescription", key: "category"},
	{file: "plugins/swarmmemo/.codex-plugin/plugin.json", field: "shortDescription", key: "category"},
	{file: "plugins/swarmmemo/plugin.json", field: "longDescription", key: "lead", tail: "With this plugin"},
	{file: "plugins/swarmmemo/.codex-plugin/plugin.json", field: "longDescription", key: "lead", tail: "With this plugin"},
	{file: "plugins/swarmmemo/skills/use-swarmmemo/SKILL.md", field: "description", key: "intro", tail: "Use when", yaml: true},
}

var lexiconMarker = regexp.MustCompile(`(?s)<!-- BEGIN LEXICON: ([\w.-]+) -->(.*?)<!-- END LEXICON -->`)

// generateLexiconMarkers fills every marker block of text.
func generateLexiconMarkers(text string) (string, int, error) {
	var err error
	n := 0
	out := lexiconMarker.ReplaceAllStringFunc(text, func(m string) string {
		sub := lexiconMarker.FindStringSubmatch(m)
		value, ok := lexiconValue(sub[1])
		if !ok {
			err = fmt.Errorf("unknown lexicon key %q", sub[1])
			return m
		}
		n++
		if strings.HasPrefix(sub[2], "\n") {
			value = "\n" + value + "\n"
		}
		return "<!-- BEGIN LEXICON: " + sub[1] + " -->" + value + "<!-- END LEXICON -->"
	})
	return out, n, err
}

// generateLexiconField rewrites one field of text.
func generateLexiconField(text string, f lexiconField) (string, error) {
	value, ok := lexiconValue(f.key)
	if !ok {
		return "", fmt.Errorf("unknown lexicon key %q", f.key)
	}
	var re *regexp.Regexp
	if f.yaml {
		re = regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(f.field) + `: (.*)$`)
	} else {
		re = regexp.MustCompile(`"` + regexp.QuoteMeta(f.field) + `": ("(?:[^"\\]|\\.)*")`)
	}
	matches := re.FindAllStringSubmatchIndex(text, -1)
	if len(matches) != 1 {
		return "", fmt.Errorf("%d %q fields, want 1", len(matches), f.field)
	}
	raw := text[matches[0][2]:matches[0][3]]
	old := raw
	if f.yaml {
		if strings.HasPrefix(raw, `"`) {
			if err := json.Unmarshal([]byte(raw), &old); err != nil {
				return "", err
			}
		}
	} else if err := json.Unmarshal([]byte(raw), &old); err != nil {
		return "", err
	}
	if f.tail != "" {
		i := strings.Index(old, f.tail)
		if i < 0 {
			return "", fmt.Errorf("%q has no %q to keep", f.field, f.tail)
		}
		value += " " + old[i:]
	}
	encoded := value
	if !f.yaml || strings.Contains(value, ": ") || strings.Contains(value, " #") || strings.ContainsAny(value[:1], `"'{[&*!|>%@`+"`") {
		var b bytes.Buffer
		enc := json.NewEncoder(&b)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(value); err != nil {
			return "", err
		}
		encoded = strings.TrimSuffix(b.String(), "\n")
	}
	return text[:matches[0][2]] + encoded + text[matches[0][3]:], nil
}

// privateOnly reports a file the public snapshot does not publish, read from
// inside that snapshot (which has no release/ directory): it is checked in the
// private tree only.
func privateOnly(file string) bool {
	if _, err := os.Stat("../../release"); !os.IsNotExist(err) {
		return false
	}
	_, err := os.Stat("../../" + file)
	return os.IsNotExist(err)
}

// TestLexiconStaticFiles holds every generated line of the static files to
// the glossary; SWARMMEMO_WRITE_GENERATED=1 (go generate) rewrites them.
func TestLexiconStaticFiles(t *testing.T) {
	write := os.Getenv("SWARMMEMO_WRITE_GENERATED") == "1"
	files := map[string]string{}
	read := func(file string) string {
		if text, ok := files[file]; ok {
			return text
		}
		raw, err := os.ReadFile("../../" + file)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	for file, min := range lexiconMarkerFiles {
		if privateOnly(file) {
			continue
		}
		text, n, err := generateLexiconMarkers(read(file))
		if err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		if n < min {
			t.Errorf("%s has %d lexicon marker blocks, want at least %d", file, n, min)
		}
		files[file] = text
	}
	for _, f := range lexiconFields {
		if privateOnly(f.file) {
			continue
		}
		text, err := generateLexiconField(read(f.file), f)
		if err != nil {
			t.Fatalf("%s: %v", f.file, err)
		}
		files[f.file] = text
	}
	for file, want := range files {
		raw, err := os.ReadFile("../../" + file)
		if err != nil {
			t.Fatal(err)
		}
		if string(raw) == want {
			continue
		}
		if write {
			if err := os.WriteFile("../../"+file, []byte(want), 0o644); err != nil {
				t.Fatal(err)
			}
			t.Logf("wrote %s", file)
			continue
		}
		t.Errorf("%s differs from the glossary's positioning block: run go generate ./internal/web", file)
	}
	// Every JSON file still parses.
	for _, f := range lexiconFields {
		if _, ok := files[f.file]; ok && !f.yaml {
			var v any
			if err := json.Unmarshal([]byte(files[f.file]), &v); err != nil {
				t.Errorf("%s: %v", f.file, err)
			}
		}
	}
}

// The generator refuses an unknown key and a field it cannot place, and
// fills a block the same way twice.
func TestLexiconGeneratorRules(t *testing.T) {
	if _, _, err := generateLexiconMarkers("<!-- BEGIN LEXICON: slogan -->x<!-- END LEXICON -->"); err == nil {
		t.Error("an unknown marker key was filled")
	}
	once, n, err := generateLexiconMarkers("a <!-- BEGIN LEXICON: category -->old<!-- END LEXICON --> b\n<!-- BEGIN LEXICON: headline -->\nold\n<!-- END LEXICON -->\n")
	if err != nil || n != 2 {
		t.Fatalf("%d blocks, %v", n, err)
	}
	if want := "a <!-- BEGIN LEXICON: category -->" + Tagline + "<!-- END LEXICON --> b\n<!-- BEGIN LEXICON: headline -->\n**" + Tagline + "**\n" + ShortDescription + "\n<!-- END LEXICON -->\n"; once != want {
		t.Errorf("filled %q, want %q", once, want)
	}
	if twice, _, _ := generateLexiconMarkers(once); twice != once {
		t.Error("filling twice changed the text")
	}
	if _, err := generateLexiconField(`{"description":"a","x":{"description":"b"}}`, lexiconField{field: "description", key: "category"}); err == nil {
		t.Error("an ambiguous field was rewritten")
	}
	got, err := generateLexiconField("---\nname: x\ndescription: old. Use when y.\n---\n", lexiconField{field: "description", key: "lead", tail: "Use when", yaml: true})
	if err != nil {
		t.Fatal(err)
	}
	if want := "description: " + fmt.Sprintf("%q", Lead()+" Use when y.") + "\n"; !strings.Contains(got, want) {
		t.Errorf("a YAML value with a colon is quoted: %q", got)
	}
}
