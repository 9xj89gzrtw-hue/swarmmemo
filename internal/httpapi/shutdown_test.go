package httpapi

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"swarmmemo/internal/board"
)

// C498: a deploy logged one 500 on GET /api/agent at the restart instant.
// SIGTERM cancels every in-flight request's context (cmd/swarmmemo serve's
// BaseContext is the signal context), and a request still running when the
// store closes (a drain that outlived the shutdown deadline) reads a closed
// database. Both are the service going away, not a fault: every handler
// answers 503 with Retry-After through the one error path, never 500.
func TestShutdownAnswers503NotInternal(t *testing.T) {
	store, err := board.Open(filepath.Join(t.TempDir(), "shutdown.db"), board.Config{ServiceID: "swarmmemo.com"})
	if err != nil {
		t.Fatal(err)
	}
	s := New(store, nil, Config{ServiceID: "swarmmemo.com"})
	check := func(name string, w *httptest.ResponseRecorder) {
		t.Helper()
		var body struct {
			Error board.Error `json:"error"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		if w.Code != 503 || w.Header().Get("Retry-After") == "" || body.Error.Code != "service_unavailable" {
			t.Fatalf("%s: %d Retry-After=%q %s, want 503 service_unavailable with Retry-After", name, w.Code, w.Header().Get("Retry-After"), w.Body)
		}
	}
	// A request whose context SIGTERM cancelled mid-read.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := httptest.NewRequest("GET", "/api/agent/nobody", nil).WithContext(ctx)
	r.RemoteAddr = "198.51.100.8:12345"
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	check("cancelled request", w)
	// A request served after the store closed.
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	check("closed store", get(s, "/api/agent/nobody", ""))
	check("closed store, list", get(s, "/api/agents", ""))
}

func TestShutdownErrorMapping(t *testing.T) {
	for _, e := range []error{context.Canceled, errClosedForTest{}} {
		if be := apiError(e); be.Status != 503 || be.RetryAfter == 0 {
			t.Errorf("apiError(%v) = %+v, want 503 with retry_after", e, be)
		}
	}
	if be := apiError(context.DeadlineExceeded); be.Status != 500 {
		t.Errorf("a deadline is not shutdown: %+v", be)
	}
}

type errClosedForTest struct{}

func (errClosedForTest) Error() string { return "query: sql: database is closed" }
