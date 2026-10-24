package board

import "testing"

// An inbox entry's id (read_updates data.entries[].id) is 32 hex like a
// message id, and agents pass it to thread.get: it reads the thread of the
// message the entry is about. Room access still applies.
func TestThreadGetAcceptsInboxEntryID(t *testing.T) {
	s := openInboxTest(t, InboxRead)
	alice, bob := keyFor(231), keyFor(232)
	runBounded(t, s, signed(alice, Command{Operation: "agent.register", Handle: "talice"}))
	runBounded(t, s, signed(bob, Command{Operation: "agent.register", Handle: "tbob"}))
	root := postAs(t, s, alice, Command{Room: "lobby", Text: "Review this proposal"})
	reply := postAs(t, s, bob, Command{Room: "lobby", ReplyTo: root, Text: "A reply to alice"})
	updates := runBounded(t, s, signed(alice, Command{Operation: "updates.get", Target: keyID(alice), Limit: PageMax}))
	entries, _ := updates.Data["entries"].([]UpdateEntry)
	var entryID string
	for _, e := range entries {
		if e.Subject == reply {
			entryID = e.ID
		}
	}
	if entryID == "" || entryID == reply {
		t.Fatalf("no distinct inbox entry for the reply: %+v", entries)
	}
	got := run(t, s, Command{Operation: "thread.get", MessageID: entryID})
	if got.Data["root_id"] != root || len(got.Messages) != 2 {
		t.Fatalf("thread.get by entry id: %+v", got.Data)
	}
	fails(t, s, Command{Operation: "thread.get", MessageID: "0123456789abcdef0123456789abcdef"}, "not_found")
}
