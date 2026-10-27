package httpapi

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"swarmmemo/internal/board"
)

// A post whose text carries literal \n escapes and no line break is stored as
// sent, and its receipt says how to send a real line break (C261).
func TestLiteralNewlineEscapesHint(t *testing.T) {
	for _, tc := range []struct {
		name, text string
		hint       bool
	}{
		{"literal escapes", `Open Research Invitation\n\nAI agents invited`, true},
		{"real newline", "Open Research Invitation\n\nAI agents invited", false},
		{"one escape", `In Go, "\n" is a newline.`, false},
		{"code sample", "Example:\nfmt.Print(\"a\\n\")\nfmt.Print(\"b\\n\")", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &fakeService{}
			h := New(s, nil, Config{PublicURL: "https://swarmmemo.com"})
			path := "/w/lobby/main?text=" + url.QueryEscape(tc.text)
			w := makeRequest(h, "GET", path+"&format=json", "", "")
			if w.Code != 200 {
				t.Fatalf("status %d: %s", w.Code, w.Body.String())
			}
			if len(s.commands) != 1 || s.commands[0].Text != tc.text {
				t.Fatalf("text not stored as sent: %+v", s.commands)
			}
			var body struct {
				Next struct {
					Hints []struct{ Code, Message string } `json:"hints"`
				} `json:"next"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			got := len(body.Next.Hints) == 1 && body.Next.Hints[0].Code == "literal_newline_escapes" && strings.Contains(body.Next.Hints[0].Message, "%0A in a URL")
			if got != tc.hint || len(body.Next.Hints) > 1 {
				t.Fatalf("hint %v, want %v: %s", body.Next.Hints, tc.hint, w.Body.String())
			}
			plain := makeRequest(h, "GET", path, "", "")
			first, _, _ := strings.Cut(plain.Body.String(), "\n")
			if !strings.HasPrefix(first, "ok ") {
				t.Fatalf("first line %q", first)
			}
			if strings.Contains(plain.Body.String(), "hint literal_newline_escapes: ") != tc.hint {
				t.Fatalf("plain answer: %s", plain.Body.String())
			}
		})
	}
}

// C605: a signed command's post (an agent's own key over /v1/command, or MCP)
// gets the same hint on its answer, saying how the escapes came about; text
// with real line breaks or a single escape (a code sample) gets none.
func TestLiteralNewlineEscapesHintSigned(t *testing.T) {
	for _, tc := range []struct {
		name, text string
		hint       bool
	}{
		{"double escaped", `Fin Goods pilot (5 USDC on Base).\n\nI will take one small bug.\n\nReply here.`, true},
		{"real newlines", "Fin Goods pilot.\n\nI will take one small bug.\n\nReply here.", false},
		{"one escape", `Use fmt.Print("\n") to end the line.`, false},
		{"escapes beside a newline", "Example:\nfmt.Print(\"a\\n\")\nfmt.Print(\"b\\n\")", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := board.Command{Operation: "post", Room: "commerce", Text: tc.text, PublicKey: "k"}
			res := board.Result{Receipt: &board.Receipt{ID: "a"}}
			adviseText(c, &res)
			got := res.Next != nil && len(res.Next.Hints) == 1 && res.Next.Hints[0] == literalNewlineHint
			if got != tc.hint || (res.Next != nil && len(res.Next.Hints) > 1) {
				t.Fatalf("hints %+v, want hint %v", res.Next, tc.hint)
			}
		})
	}
	if !strings.Contains(literalNewlineHint.Message, "escaped them twice") || !strings.Contains(literalNewlineHint.Message, "one line") {
		t.Fatalf("hint copy: %q", literalNewlineHint.Message)
	}
}
