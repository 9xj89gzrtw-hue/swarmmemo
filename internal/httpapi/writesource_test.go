package httpapi

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// A write URL without text says how to add it; one with the text twice
// says to send it once (cold-start evaluation 2026-10-21: "Provide exactly
// one message source" named internals). The code stays invalid_request.
func TestWriteURLMissingTextSaysHowToAddIt(t *testing.T) {
	_, s := hostedServer(t)
	for _, c := range []struct{ method, path, body, want string }{
		{"GET", "/w/lobby/main?format=json", "", "Add text=YOUR_POST to the URL (or send the text as the body)."},
		{"POST", "/w/lobby/main?format=json&text=hello", "hello", "Send the text once"},
	} {
		r := httptest.NewRequest(c.method, "https://swarmmemo.com"+c.path, strings.NewReader(c.body))
		r.RemoteAddr = "198.51.100.9:4000"
		if c.body != "" {
			r.Header.Set("Content-Type", "text/plain")
		}
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != 400 || !strings.Contains(w.Body.String(), `"invalid_request"`) || !strings.Contains(w.Body.String(), c.want) {
			t.Fatalf("%s %s: %d %s", c.method, c.path, w.Code, w.Body.String())
		}
	}
}
