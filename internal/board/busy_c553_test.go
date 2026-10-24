package board

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// C553: two POST /v1/command failed at once with "database is locked (5)
// (SQLITE_BUSY)" while the operator CLI was writing the live database.

// openAt is openTest at a known path, so a second process (the operator CLI)
// can open the same file.
func openAt(t *testing.T, path string, c Config) *Store {
	t.Helper()
	s, err := Open(path, c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	s.now = func() time.Time { return time.Unix(testTime, 0) }
	return s
}

// externalWriter is another process's connection to the same file, opened as
// the operator CLI's was before C553 (deferred transactions).
func externalWriter(t *testing.T, path, pragmas string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", (&url.URL{Scheme: "file", Path: path, RawQuery: pragmas}).String())
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// TestDeferredUpgradeFailsAtOnce is the diagnosis: a deferred transaction
// that read and then writes while another connection holds the write lock
// gets SQLITE_BUSY (5) at once, without the busy handler, and SQLITE_BUSY_SNAPSHOT
// (517) after that connection committed; an IMMEDIATE one waits.
func TestDeferredUpgradeFailsAtOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.db")
	const deferred = "_pragma=busy_timeout(5000)"
	server, operator := externalWriter(t, path, deferred), externalWriter(t, path, deferred)
	if _, err := server.Exec("PRAGMA journal_mode=WAL; CREATE TABLE t(x)"); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, commit := range []bool{false, true} {
		tx, err := server.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		var n int
		if err = tx.QueryRow("SELECT count(*) FROM t").Scan(&n); err != nil {
			t.Fatal(err)
		}
		other, err := operator.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = other.Exec("INSERT INTO t VALUES(1)"); err != nil {
			t.Fatal(err)
		}
		if commit {
			if err = other.Commit(); err != nil {
				t.Fatal(err)
			}
		}
		start := time.Now()
		_, err = tx.Exec("INSERT INTO t VALUES(2)")
		took := time.Since(start)
		_ = tx.Rollback()
		_ = other.Rollback()
		if !IsBusy(err) || took > time.Second {
			t.Fatalf("commit=%v: want an instant busy error, got %v after %v", commit, err, took)
		}
		want := "(5) (SQLITE_BUSY)" // the prod log line
		if commit {
			want = "(517)"
		}
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("commit=%v: %v, want %s", commit, err, want)
		}
	}
}

// TestCommandWaitsForExternalWriter: with _txlock=immediate a command begun
// while another process holds the write lock waits for it (busy_timeout)
// and succeeds, instead of failing at once.
func TestCommandWaitsForExternalWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "board.sqlite")
	s := openAt(t, path, Config{})
	run(t, s, signed(keyFor(1), Command{Operation: "post", Room: "lobby", Text: "before"}))
	operator := externalWriter(t, path, "_pragma=busy_timeout(5000)")
	ctx := context.Background()
	for i := range 3 {
		tx, err := operator.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		// A write that changes the file, as moderate or params set does.
		if _, err = tx.Exec("INSERT OR REPLACE INTO meta(key,value) VALUES('c553_test',?)", time.Now().String()); err != nil {
			t.Fatal(err)
		}
		released := make(chan struct{})
		go func() {
			time.Sleep(300 * time.Millisecond)
			_ = tx.Commit()
			close(released)
		}()
		start := time.Now()
		res, err := s.Execute(testContext, signed(keyFor(1), Command{Operation: "post", Room: "lobby", Text: "during " + string(rune('a'+i))}), "test-origin")
		took := time.Since(start)
		<-released
		if err != nil || !res.OK {
			t.Fatalf("post %d during an external write: %v (after %v)", i, err, took)
		}
		if took < 200*time.Millisecond {
			t.Fatalf("post %d finished in %v: it should have waited for the external writer", i, took)
		}
	}
}

// TestBusyAnswersBusy: past busy_timeout the error is IsBusy, and ErrBusy is
// the 503 busy with Retry-After the transports answer.
func TestBusyAnswersBusy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.db")
	a, b := externalWriter(t, path, "_pragma=busy_timeout(0)&_txlock=immediate"), externalWriter(t, path, "_pragma=busy_timeout(0)&_txlock=immediate")
	if _, err := a.Exec("PRAGMA journal_mode=WAL; CREATE TABLE t(x)"); err != nil {
		t.Fatal(err)
	}
	tx, err := a.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	_, err = b.Begin()
	if !IsBusy(err) {
		t.Fatalf("want busy, got %v", err)
	}
	if IsBusy(errors.New("database is locked")) || IsBusy(nil) {
		t.Fatal("only a SQLite error is busy")
	}
	if e := ErrBusy(); e.Status != 503 || e.Code != "busy" || e.RetryAfter < 1 {
		t.Fatalf("ErrBusy = %+v", e)
	}
}

// TestReadOnlyOpen: an operator read opens the live database read-only: it
// reads, refuses every write, changes nothing on disk (data_version on the
// server's connection stays put), creates no key file and arms no timer.
func TestReadOnlyOpen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "board.sqlite")
	features := Features{Moderation: true, AnonPrefix: true}
	live := openAt(t, path, Config{Features: features})
	run(t, live, signed(keyFor(1), Command{Operation: "post", Room: "lobby", Text: "hello"}))
	conn, err := live.db.Conn(testContext) // the server's one connection, held for data_version
	if err != nil {
		t.Fatal(err)
	}
	version := func() int64 {
		var v int64
		if err := conn.QueryRowContext(testContext, "PRAGMA data_version").Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	before := version()
	entries := func() []string {
		list, _ := os.ReadDir(dir)
		names := []string{}
		for _, e := range list {
			if !strings.HasSuffix(e.Name(), "-wal") && !strings.HasSuffix(e.Name(), "-shm") {
				names = append(names, e.Name())
			}
		}
		return names
	}
	files := strings.Join(entries(), ",")
	ro, err := Open(path, Config{ReadOnly: true, Features: features, LogKeyFile: filepath.Join(dir, "absent-log.key"), SignalsKeyFile: filepath.Join(dir, "absent-signals.key")})
	if err != nil {
		t.Fatal(err)
	}
	ro.now = live.now
	if !ro.config.Operator {
		t.Fatal("ReadOnly implies Operator")
	}
	if ro.design0.salts.timer != nil {
		t.Fatal("a read-only open armed the salt expiry timer")
	}
	if ro.generation != live.generation {
		t.Fatal("a read-only open must read the generation, not make one")
	}
	if _, err = ro.ReadReferrerStats(testContext, time.Unix(testTime, 0), 7); err != nil {
		t.Fatal("read:", err)
	}
	if _, err = ro.FunnelKPIFor(testContext, 7); err != nil {
		t.Fatal("read:", err)
	}
	if _, err = ro.Moderation().Alerts(testContext, 10); err != nil {
		t.Fatal("read:", err)
	}
	if _, err = ro.Execute(testContext, signed(keyFor(2), Command{Operation: "post", Room: "lobby", Text: "refused"}), "test-origin"); err == nil {
		t.Fatal("a read-only store accepted a post")
	}
	if _, err = ro.db.Exec("INSERT INTO meta(key,value) VALUES('ro','x')"); err == nil || !strings.Contains(err.Error(), "readonly") {
		t.Fatalf("a read-only store wrote: %v", err)
	}
	if err = ro.Close(); err != nil {
		t.Fatal(err)
	}
	if after := version(); after != before {
		t.Fatalf("the read-only open changed the database (data_version %d -> %d)", before, after)
	}
	if got := strings.Join(entries(), ","); got != files {
		t.Fatalf("files changed: %s -> %s", files, got)
	}
	_ = conn.Close()
	// The live server writes on as before.
	run(t, live, signed(keyFor(1), Command{Operation: "post", Room: "lobby", Text: "after"}))
}

// TestReadOnlyOpenRefusesMigration: a read-only open never migrates.
func TestReadOnlyOpenRefusesMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "board.sqlite")
	s, err := Open(path, Config{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec("PRAGMA user_version=45"); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	if _, err = Open(path, Config{ReadOnly: true}); err == nil || !strings.Contains(err.Error(), "never migrates") {
		t.Fatalf("want a refusal, got %v", err)
	}
	if _, err = Open(filepath.Join(t.TempDir(), "absent.sqlite"), Config{ReadOnly: true}); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a read-only open created a database: %v", err)
	}
}
