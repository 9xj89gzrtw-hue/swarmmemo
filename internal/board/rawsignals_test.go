package board

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func rawSignalCount(t *testing.T, s *Store) int {
	t.Helper()
	var n int
	if err := s.rawSignals.db.QueryRow("SELECT count(*) FROM raw_signals").Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// C452: an accepted write leaves one sealed raw record with its address and
// headers, credentials redacted; a read, a refused write and an exact retry
// leave none; the blob holds nothing in clear; records go after
// RawSignalRetentionDays.
func TestRawSignalsSealedAndPruned(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "board.sqlite"), Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.now = func() time.Time { return time.Unix(testTime, 0) }
	alice := keyFor(61)
	ctx := WithRequestSignals(WithVia(context.Background(), "command"), RequestSignals{
		UserAgent: "raw-canary/1",
		Headers: map[string][]string{
			"Authorization":            {"Bearer smh_secret-token-c452"},
			"cookie":                   {"sid=cookie-c452"},
			"X-Swarmmemo-Bridge-Token": {"bridge-c452"},
			"User-Agent":               {"raw-canary/1 \x1b[31m"},
			"Accept-Language":          {"en"},
			"Referer":                  {"https://swarmmemo.com/mcp/smh_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA?x=1"},
		},
		RemoteAddr: "127.0.0.1:5000", ForwardedFor: "203.0.113.200", Proto: "HTTP/2.0", TLS: "TLS 1.3",
		MCPClient: &MCPClientInfo{Name: "claude-ai", Version: "1.2"},
	})
	post := signed(alice, Command{Operation: "post", Room: "lobby", Text: "raw", RequestID: "r1"})
	res, err := s.Execute(ctx, post, "203.0.113.200")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Execute(ctx, post, "203.0.113.200"); err != nil { // exact retry
		t.Fatal(err)
	}
	if _, err = s.Execute(ctx, Command{Operation: "messages.list", Room: "lobby"}, "203.0.113.200"); err != nil { // a read
		t.Fatal(err)
	}
	if _, err = s.Execute(ctx, signed(alice, Command{Operation: "vote", MessageID: res.Receipt.ID, Data: `{"value":1}`, RequestID: "self"}), "203.0.113.200"); errCode(err) != "self_vote" {
		t.Fatalf("self vote: %v", err)
	}
	if n := rawSignalCount(t, s); n != 1 {
		t.Fatalf("%d raw records, want 1", n)
	}
	var sealed []byte
	if err = s.rawSignals.db.QueryRow("SELECT sealed FROM raw_signals").Scan(&sealed); err != nil {
		t.Fatal(err)
	}
	for _, clear := range []string{"203.0.113.200", "raw-canary", "secret-token", "cookie-c452", "claude-ai"} {
		if bytes.Contains(sealed, []byte(clear)) {
			t.Fatalf("%q in the sealed blob", clear)
		}
	}
	got, err := s.RawSignalsForObject(context.Background(), res.Receipt.ID)
	if err != nil || len(got) != 1 {
		t.Fatalf("%v %v", got, err)
	}
	r := got[0]
	if r.IP != "203.0.113.200" || r.Account != keyID(alice) || r.Signer != keyID(alice) || r.Room != "lobby" || r.RequestID != "r1" || r.Via != "command" ||
		r.RemoteAddr != "127.0.0.1:5000" || r.ForwardedFor != "203.0.113.200" || r.Proto != "HTTP/2.0" || r.TLS != "TLS 1.3" || r.CreatedAt != testTime ||
		r.MCPClient == nil || r.MCPClient.Name != "claude-ai" {
		t.Fatalf("record %+v", r)
	}
	for _, h := range []string{"Authorization", "Cookie", "X-Swarmmemo-Bridge-Token"} {
		if v := r.Headers[h]; len(v) != 1 || v[0] != rawRedacted {
			t.Fatalf("%s: %v", h, v)
		}
	}
	if v := r.Headers["User-Agent"]; len(v) != 1 || v[0] != "raw-canary/1 [31m" {
		t.Fatalf("user agent not cleaned: %q", v)
	}
	if v := r.Headers["Referer"]; len(v) != 1 || v[0] != "https://swarmmemo.com/mcp/<redacted>?<redacted>" {
		t.Fatalf("referer %q", v)
	}
	if acct, err := s.RawSignalsForAccount(context.Background(), keyID(alice), 30); err != nil || len(acct) != 1 || acct[0].IP != r.IP {
		t.Fatalf("account view %v %v", acct, err)
	}
	if n, err := s.RawSignalCount(context.Background(), res.Receipt.ID); err != nil || n != 1 {
		t.Fatalf("count %d %v", n, err)
	}

	// Files: key and database 0600 beside the board; a reopen reads the
	// record, another key cannot.
	for _, name := range []string{RawSignalsKeyFileName, RawSignalsDBFileName} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v %v", name, info, err)
		}
	}
	other, err := Open(filepath.Join(dir, "board.sqlite"), Config{ReadOnly: true, Operator: true, RawSignalsKeyFile: filepath.Join(dir, "absent.key")})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := other.RawSignalsForObject(context.Background(), res.Receipt.ID); err != nil || len(got) != 1 || got[0].Unreadable == "" || got[0].IP != "" {
		t.Fatalf("another key opened it: %+v %v", got, err)
	}
	other.Close()
	if _, err = os.Stat(filepath.Join(dir, "absent.key")); !os.IsNotExist(err) {
		t.Fatalf("a read-only open made a key: %v", err)
	}

	// Kept 365 days, then deleted; hashed rows keep their own window.
	s.now = func() time.Time { return time.Unix(testTime+(RawSignalRetentionDays-1)*86400, 0) }
	if _, err = s.PruneWriteSignals(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := rawSignalCount(t, s); n != 1 {
		t.Fatalf("pruned early: %d", n)
	}
	s.now = func() time.Time { return time.Unix(testTime+RawSignalRetentionDays*86400+3600, 0) }
	if _, err = s.PruneWriteSignals(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := rawSignalCount(t, s); n != 0 {
		t.Fatalf("%d raw records after %d days", n, RawSignalRetentionDays)
	}
}

func TestRawSecretHeader(t *testing.T) {
	for name, want := range map[string]bool{"Authorization": true, "Proxy-Authorization": true, "Cookie": true, "X-Payment": true, "Payment-Signature": true,
		"Swarmmemo-Gate-Token": true, "X-Api-Key": true, "X-Client-Secret": true, "User-Agent": false, "Accept": false, "X-Forwarded-For": false, "Content-Type": false} {
		if rawSecretHeader(name) != want {
			t.Errorf("%s: want %v", name, want)
		}
	}
}
