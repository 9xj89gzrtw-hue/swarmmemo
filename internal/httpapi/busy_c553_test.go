package httpapi

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
)

// TestBusyIsNot500 (C553): SQLite's "database is locked", wrapped or not,
// answers 503 busy with Retry-After, never 500 internal.
func TestBusyIsNot500(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.db")
	open := func() *sql.DB {
		db, err := sql.Open("sqlite", (&url.URL{Scheme: "file", Path: path, RawQuery: "_pragma=busy_timeout(0)&_txlock=immediate"}).String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		return db
	}
	a, b := open(), open()
	if _, err := a.Exec("PRAGMA journal_mode=WAL; CREATE TABLE t(x)"); err != nil {
		t.Fatal(err)
	}
	tx, err := a.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	_, busy := b.Exec("INSERT INTO t VALUES(1)")
	if busy == nil {
		t.Fatal("want a busy error")
	}
	for _, e := range []error{busy, fmt.Errorf("post: %w", busy)} {
		w := httptest.NewRecorder()
		writeError(w, e)
		var body struct {
			Error struct{ Code string } `json:"error"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		if w.Code != 503 || w.Header().Get("Retry-After") != "1" || body.Error.Code != "busy" {
			t.Fatalf("%v: got %d Retry-After %q code %q", e, w.Code, w.Header().Get("Retry-After"), body.Error.Code)
		}
	}
}
