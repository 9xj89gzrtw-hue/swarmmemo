package board

import (
	"net"
	"regexp"
	"strings"
	"testing"

	"swarmmemo/internal/services"
)

var eraseMailRE = regexp.MustCompile(`^rcv\.([a-z2-7]{32})@`)

// Deleting a receiver erases its items (a mail's sender address included)
// and the inbox entries that point at them, in the delete's transaction,
// and says how many; another receiver's items and entries stay (C500).
func TestReceiverDeleteErasesItems(t *testing.T) {
	s := openInboxTest(t, InboxRead)
	bob := keyFor(231)
	runBounded(t, s, signed(bob, Command{Operation: "agent.register", Handle: "erasebob"}))
	account := keyAccount(t, s, bob)
	create := func(label, request string) (id, token, mail string) {
		t.Helper()
		created := runBounded(t, s, svcCall(bob, "receiver", "create", map[string]any{"label": label, "screen": false}, 5, request))
		url, _ := svcField(t, created.Data, "result", "url").(string)
		parts := strings.Split(url[strings.Index(url, "/in/")+4:], "/")
		address, _ := svcField(t, created.Data, "result", "email").(string)
		m := eraseMailRE.FindStringSubmatch(address)
		if len(parts) != 2 || m == nil {
			t.Fatalf("create: %+v", created.Data)
		}
		return parts[0], parts[1], m[1]
	}
	deliver := func(d services.Delivery) string {
		t.Helper()
		d.Source = net.ParseIP("198.51.100.62")
		receipt, err := s.Receive(testContext, d)
		if err != nil {
			t.Fatal(err)
		}
		return receipt.Item
	}
	gone, goneToken, goneMail := create("gone", "c500-gone")
	kept, keptToken, _ := create("kept", "c500-kept")
	mail := `{"kind":"email","from":"human@example.org","subject":"hi","date":"Tue, 20 Oct 2026 10:00:00 +0000","message_id":"<m1@example.org>","text":"hello agent"}`
	erased := []string{
		deliver(services.Delivery{ID: gone, Token: goneToken, ContentType: "application/json", Body: []byte(`{"job":1}`)}),
		deliver(services.Delivery{Mail: true, Token: goneMail, ContentType: "application/json", Body: []byte(mail)}),
	}
	stays := deliver(services.Delivery{ID: kept, Token: keptToken, ContentType: "application/json", Body: []byte(`{"job":2}`)})

	count := func(query string, args ...any) int {
		t.Helper()
		var n int
		if err := s.db.QueryRow(query, args...).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	entries := func(item string) int {
		return count("SELECT count(*) FROM inbox_entries WHERE account=? AND kind='received' AND subject=?", account, item)
	}
	for _, item := range append(erased, stays) {
		if entries(item) != 1 {
			t.Fatalf("item %s has no inbox entry before the delete", item)
		}
	}

	deleted := runBounded(t, s, svcCall(bob, "receiver", "delete", map[string]any{"id": gone}, 1, "c500-delete"))
	if n, _ := svcField(t, deleted.Data, "result", "erased").(float64); n != 2 || svcField(t, deleted.Data, "result", "receiver", "state") != "deleted" {
		t.Fatalf("delete: %+v", deleted.Data)
	}
	for _, item := range erased {
		if count("SELECT count(*) FROM receiver_items WHERE id=?", item) != 0 || entries(item) != 0 {
			t.Fatalf("item %s outlived its receiver", item)
		}
	}
	if count("SELECT count(*) FROM receiver_items WHERE receiver=?", gone) != 0 || count("SELECT count(*) FROM receiver_items WHERE body LIKE '%human@example.org%'") != 0 {
		t.Fatal("the deleted receiver's items remain")
	}
	if count("SELECT count(*) FROM receiver_items WHERE id=?", stays) != 1 || entries(stays) != 1 {
		t.Fatal("another receiver's item went with it")
	}
	read := runBounded(t, s, svcRead(bob, "receiver", "items", map[string]any{}))
	list, _ := svcField(t, read.Data, "result", "items").([]any)
	if len(list) != 1 || svcField(t, list[0], "id") != stays {
		t.Fatalf("items after the delete: %+v", read.Data)
	}

	// Delete is idempotent: a second one finds nothing left to erase.
	again := runBounded(t, s, svcCall(bob, "receiver", "delete", map[string]any{"id": gone}, 1, "c500-delete-again"))
	if n, ok := svcField(t, again.Data, "result", "erased").(float64); !ok || n != 0 {
		t.Fatalf("second delete: %+v", again.Data)
	}
}
