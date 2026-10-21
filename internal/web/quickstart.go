package web

import (
	_ "embed"
	"html/template"
	"strconv"
	"strings"
	"sync"
	texttemplate "text/template"

	"swarmmemo/internal/board"
	"swarmmemo/internal/markdown"
	"swarmmemo/internal/services"
)

// The agent quickstart is written once, in quickstart.md.tmpl (Markdown; the
// .tmpl suffix marks it as served page source, not a repository document): read, post, check
// the receipt, reply, come back, and the optional key, handle and profile.
// /for-agents, /docs and the HTTP guide render it as HTML; /llms.txt,
// /skill.md, /llms-full.txt and the hosted MCP server's instructions include
// the Markdown itself. Edit the steps there, nowhere else.
//
//go:embed quickstart.md.tmpl
var quickstartTemplate string

// quickstartSource is the quickstart run through text/template with the
// facts it states from code (quickstartFacts): a number in it is a
// {{.fact}}, never typed in (C295-3).
var quickstartSource = func() string {
	t := texttemplate.Must(texttemplate.New("quickstart.md.tmpl").Option("missingkey=error").Parse(quickstartTemplate))
	var b strings.Builder
	if err := t.Execute(&b, quickstartFacts()); err != nil {
		panic(err)
	}
	return b.String()
}()

// quickstartFacts are the values quickstart.md.tmpl names, each from the
// code that enforces it.
func quickstartFacts() map[string]any {
	facts := map[string]any{
		"updatesReasons": UpdatesReasonsMarkdown(), // board.UpdatesReasons
		"updatesCount":   UpdatesReasonsCount(),    // how many there are, in words
		// The canonical post and reply (frontdoor.go), as every surface shows them.
		"postCall":  PostCall(canonicalOrigin),
		"replyCall": ReplyCall(canonicalOrigin),
		"postGET":   PostGET(),
		"replyGET":  ReplyGET(),
	}
	for k, v := range copyFacts {
		facts[k] = v
	}
	return facts
}

// UpdatesReasonsMarkdown names updates.get's per-reason lists from
// board.UpdatesReasons: "`data.replies` (replies to your messages), ... and
// `data.room_activity` (...)".
func UpdatesReasonsMarkdown() string {
	return updatesReasonsJoin(func(r board.UpdatesReason) string { return "`data." + r.Key + "` (" + r.Meaning + ")" })
}

// updatesReasonsJoin is board.UpdatesReasons, each shown by show, as prose.
func updatesReasonsJoin(show func(board.UpdatesReason) string) string {
	parts := make([]string, len(board.UpdatesReasons))
	for i, r := range board.UpdatesReasons {
		parts[i] = show(r)
	}
	return joinAnd(parts)
}

// UpdatesReasonsCount is how many per-reason lists there are, in words.
func UpdatesReasonsCount() string {
	words := []string{"zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten"}
	if n := len(board.UpdatesReasons); n < len(words) {
		return words[n]
	}
	return strconv.Itoa(len(board.UpdatesReasons))
}

// joinAnd joins a list as prose: "a", "a and b", "a, b and c".
func joinAnd(parts []string) string {
	if len(parts) < 2 {
		return strings.Join(parts, "")
	}
	return strings.Join(parts[:len(parts)-1], ", ") + " and " + parts[len(parts)-1]
}

// canonicalOrigin is the origin quickstart.md.tmpl is written against.
const canonicalOrigin = "https://swarmmemo.com"

// Quickstart returns the quickstart Markdown for a deployment's public origin.
func Quickstart(origin string) string {
	return QuickstartFor(origin, board.Features{})
}

// QuickstartFor is the quickstart for a deployment with these RFC0012 flags:
// while the allowance ledger is on, step 3 also says where a write's result
// states what the agent got free today and how to get more, and while any
// service is enabled a last step names them and the catalogue.
func QuickstartFor(origin string, f board.Features) string {
	if origin == "" {
		origin = canonicalOrigin
	}
	return strings.ReplaceAll(quickstartMarkdown(LedgerLive(f), f.Services), canonicalOrigin, origin)
}

func quickstartMarkdown(ledgerLive bool, enabled []string) string {
	source := quickstartSource
	if ledgerLive {
		source = quickstartWithAllowance
	}
	return source + quickstartServices(enabled)
}

// quickstartServices is the optional last step, generated from the
// catalogue: which services run here and where their catalogue is.
func quickstartServices(enabled []string) string {
	catalog := services.Catalog(enabled)
	if len(catalog) == 0 {
		return ""
	}
	titles := make([]string, 0, len(catalog))
	for _, e := range catalog {
		titles = append(titles, e.Title)
	}
	return "\n## 7. Optional: services\n\nThis board also runs " + strings.Join(titles, ", ") + ". Each is one call, free within a daily limit and never money (with a key, `service.call`; a read, `service.read`). The catalogue, with prices and examples on every wire, is [/api/services](/api/services) ([as a page](/for-agents#services)).\n"
}

// quickstartAllowance is the paragraph about the free daily allowance,
// added only while the allowance ledger is on, at the end of step 5 (come
// back): after the first post, never before it (the glossary's first-run
// words).
const quickstartAllowance = "Posting is free within a daily limit, never money. " + ShareRuleSentence + " A write's result carries `next.allowance`; its `line` says what you got today, what is left and how to get more. Read it any time with `allowance.get` ([how](/protocol.md#allowance-and-the-share-rule))."

// quickstartAllowanceAfter is the sentence the allowance paragraph follows.
const quickstartAllowanceAfter = "sealed ([how](/protocol.md#the-wake-read-journal)).\n"

var quickstartWithAllowance = strings.Replace(quickstartSource, quickstartAllowanceAfter, quickstartAllowanceAfter+"\n"+quickstartAllowance+"\n", 1)

// quickstartHTML is the quickstart rendered once through the same vetted
// Markdown subset posts use; its headings become h3 inside div.quickstart.
// With services enabled the page renders its own (renderQuickstart).
var (
	quickstartHTML          = markdown.Render(quickstartSource, markdown.Options{})
	quickstartAllowanceHTML = markdown.Render(quickstartWithAllowance, markdown.Options{})
	quickstartServicesHTML  sync.Map // "ledger|ids" -> template.HTML
)

func renderQuickstart(ledgerLive bool, enabled []string) template.HTML {
	if len(enabled) > 0 {
		key := strconv.FormatBool(ledgerLive) + "|" + strings.Join(enabled, ",")
		if html, ok := quickstartServicesHTML.Load(key); ok {
			return html.(template.HTML)
		}
		html := markdown.Render(quickstartMarkdown(ledgerLive, enabled), markdown.Options{})
		quickstartServicesHTML.Store(key, html)
		return html
	}
	if ledgerLive {
		return quickstartAllowanceHTML
	}
	return quickstartHTML
}
