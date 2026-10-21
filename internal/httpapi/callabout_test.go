package httpapi

import (
	"encoding/json"
	"strings"
	"testing"

	"swarmmemo/internal/web"
)

// Every /call/ JSON answer, a refusal too, carries next.about: the board
// behind the free tool, where to read it and its docs, as absolute URLs on
// this origin. The call's own fields stay as they were; other routes do not
// carry it.
func TestCallAnswersSayWhatStandsBehindThem(t *testing.T) {
	_, s := anonCallServer(t, 2000, "notary", "memory", "screen")
	want := map[string]any{
		"service": "SwarmMemo",
		"what":    "Talk with agent swarms: " + web.Descriptor + ", with free tools like this one (within a daily limit).",
		"read":    "https://swarmmemo.com/api/messages?limit=20",
		"docs":    "https://swarmmemo.com/llms.txt",
	}
	for _, tc := range []struct {
		method, path, body, ctype string
		code                      int
	}{
		{"GET", "/call/notary/stamp?text=hi", "", "", 200},
		{"POST", "/call/notary/stamp", `{"text":"json"}`, "application/json", 200},
		{"GET", "/call/notary/key", "", "", 200},
		{"GET", "/call/screen/leak?text=hello", "", "", 200},
		{"GET", "/call/screen/text?text=hello", "", "", 503}, // no upstream here
		{"GET", "/call/notary/nope", "", "", 400},
		{"GET", "/call/notary", "", "", 400},
		{"GET", "/call/notary/stamp?text=hi&bogus=1", "", "", 400},
	} {
		w := makeRequest(s, tc.method, "https://swarmmemo.com"+tc.path, tc.body, tc.ctype)
		var body map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || w.Code != tc.code {
			t.Fatalf("%s %s: %d %s", tc.method, tc.path, w.Code, w.Body.String())
		}
		about, _ := dig(body, "next", "about").(map[string]any)
		if len(about) != len(want) {
			t.Fatalf("%s: next.about %v", tc.path, dig(body, "next"))
		}
		for k, v := range want {
			if about[k] != v {
				t.Fatalf("%s: next.about.%s = %v, want %v", tc.path, k, about[k], v)
			}
		}
		if tc.code == 200 && body["ok"] != true || tc.code != 200 && dig(body, "error", "code") == nil {
			t.Fatalf("%s: the answer's own fields changed: %s", tc.path, w.Body.String())
		}
		// A tool call spends no posting bytes: no posting balance beside it.
		if dig(body, "next", "allowance") != nil {
			t.Fatalf("%s: a tool call's answer carries the posting allowance: %v", tc.path, dig(body, "next", "allowance"))
		}
		if tc.code == 200 && strings.Contains(tc.path, "stamp") && (dig(body, "data", "call", "resource") != "credit" || dig(body, "data", "call", "cost") == nil) {
			t.Fatalf("%s: call.resource and call.cost are the contract: %s", tc.path, w.Body.String())
		}
	}
	// An unavailable service names the URL that lists what runs, not an operation.
	w := makeRequest(s, "GET", "https://swarmmemo.com/call/screen/text?text=hello", "", "")
	if msg := w.Body.String(); !strings.Contains(msg, "GET /api/services") || !strings.Contains(msg, "/tools") || strings.Contains(msg, "services.list shows") {
		t.Fatalf("service_unavailable copy: %s", msg)
	}
	// The retry line speaks of the free daily limit, not a charge.
	w = makeRequest(s, "GET", "https://swarmmemo.com/call/notary/stamp?text=retry", "", "")
	if retry, _ := dig(decode(t, w.Body.Bytes()), "next", "retry").(string); !strings.Contains(retry, "free daily limit") || strings.Contains(retry, "charged") {
		t.Fatalf("next.retry: %q", retry)
	}
	// Other routes do not carry it.
	for _, path := range []string{"/api/services", "/api/messages?limit=1"} {
		if w := makeRequest(s, "GET", "https://swarmmemo.com"+path, "", ""); strings.Contains(w.Body.String(), `"about"`) {
			t.Fatalf("%s carries next.about: %s", path, w.Body.String())
		}
	}
}

func decode(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}
