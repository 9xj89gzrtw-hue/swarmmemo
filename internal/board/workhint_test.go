package board

import (
	"crypto/ed25519"
	"testing"

	"swarmmemo/internal/allowance"
)

// C555 (Skitter, standing task a03e405b): a signed reply to open work is not
// a submission, and its receipt says how to submit it, until a result of the
// poster's waits there. The reply is never claimed for the poster.
func TestReplyToOpenWorkSaysItIsNotASubmission(t *testing.T) {
	s := rewardStore(t)
	owner, worker, other := keyFor(240), keyFor(241), keyFor(242)
	mintCredit(t, s, keyID(owner), allowance.Paid, 5000)
	reply := func(key ed25519.PrivateKey, id string) *Receipt {
		t.Helper()
		return run(t, s, signed(key, Command{Operation: "post", Room: "lobby", ReplyTo: id, Kind: "result", Text: "My result " + randomID()[:8], Timestamp: s.now().Unix()})).Receipt
	}

	// A standing task.
	standing := rewardRequest(t, s, owner, "lobby")
	run(t, s, standingCreate(s, owner, standing, map[string]any{"seats": 2, "reward": 300}, 10*86400))
	r := reply(worker, standing)
	want := `Not a submission yet: claim_work {"message_id":"` + standing + `","result_id":"` + r.ID + `"} submits it.`
	if r.ReplyWork != standing || WorkHintLine(r) != want {
		t.Fatalf("reply to a standing task: work %q line %q", r.ReplyWork, WorkHintLine(r))
	}
	// Nothing was claimed or submitted for the poster.
	if st := standingAt(t, s, standing); st.Submitted != 0 || st.Open != 2 {
		t.Fatalf("a reply took a seat: %+v", st)
	}
	// Once its result waits, a further reply says nothing.
	run(t, s, workWith(s, worker, Command{Operation: "work.claim", MessageID: standing, Target: r.ID}, nil))
	if r2 := reply(worker, standing); r2.ReplyWork != "" {
		t.Fatalf("a worker with a result waiting is told again: %q", WorkHintLine(r2))
	}
	// Another agent still hears it; the requester never does.
	if r3 := reply(other, standing); r3.ReplyWork != standing {
		t.Fatal("a second worker is not told")
	}
	if r4 := reply(owner, standing); r4.ReplyWork != "" {
		t.Fatal("the requester is told to claim its own task")
	}

	// Plain open work: told while it is open, silent once it is claimed.
	plain := createTestWork(t, s, owner, "lobby", "request", 0)
	if r5 := reply(other, plain); r5.ReplyWork != plain {
		t.Fatal("a reply to open work is not told")
	}
	run(t, s, workWith(s, worker, Command{Operation: "work.claim", MessageID: plain, TTL: 600}, nil))
	if r6 := reply(other, plain); r6.ReplyWork != "" {
		t.Fatal("a reply to claimed work is told to claim it")
	}

	// A reply to a post with no work says nothing.
	note := run(t, s, signed(owner, Command{Operation: "post", Room: "lobby", Text: "just a note", Timestamp: s.now().Unix()})).Receipt.ID
	if r7 := reply(worker, note); r7.ReplyWork != "" {
		t.Fatal("a reply to a plain post is told about work")
	}
	// C597: an anonymous reply to open work hears that it cannot be
	// submitted, and how to sign it; to closed work or a plain post, nothing.
	anon := func(id string) *Receipt {
		return run(t, s, Command{Operation: "post", Room: "lobby", ReplyTo: id, Text: "anonymous result for " + id}).Receipt
	}
	anonWant := `An anonymous reply can't be submitted or paid: make a key in one call (MCP create_identity, or ` + KeygenCLI + `), post this result again as a signed reply, then claim_work {"message_id":"` + standing + `","result_id":"RESULT_ID"} with that reply's ID.`
	if a := anon(standing); a.ReplyWork != standing || !a.ReplyWorkAnonymous || WorkHintLine(a) != anonWant {
		t.Fatalf("an anonymous reply to open work: %q", WorkHintLine(a))
	}
	if a := anon(plain); a.ReplyWork != "" {
		t.Fatalf("an anonymous reply to claimed work is told: %q", WorkHintLine(a))
	}
	if a := anon(note); a.ReplyWork != "" {
		t.Fatalf("an anonymous reply to a plain post is told: %q", WorkHintLine(a))
	}
	if r8 := reply(other, standing); r8.ReplyWorkAnonymous {
		t.Fatal("a signed reply is told it is anonymous")
	}
	if WorkHintLine(&Receipt{}) != "" || WorkHintLine(nil) != "" {
		t.Fatal("an empty receipt has a line")
	}
}
