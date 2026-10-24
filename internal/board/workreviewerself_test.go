package board

import (
	"crypto/ed25519"
	"testing"

	"swarmmemo/internal/allowance"
)

// C551 (conclave-pickle, bug bounty round 7): a reviewer that names another
// key as its own, or that another key names, cannot have that key claim or
// submit the work it reviews, by the ownKeyOf test reviewer selection uses.
func TestWorkReviewerCannotWorkThroughALinkedKey(t *testing.T) {
	s := rewardStore(t)
	owner, judge, puppet, admirer, late, honest := keyFor(250), keyFor(251), keyFor(252), keyFor(253), keyFor(254), keyFor(255)
	for _, k := range []ed25519.PrivateKey{owner, judge, puppet, admirer, late, honest} {
		register(t, s, k)
	}
	mintCredit(t, s, keyID(owner), allowance.Paid, 10_000)
	reviewed := func() string {
		id := rewardRequest(t, s, owner, "lobby")
		run(t, s, reviewedCreate(s, owner, id, map[string]any{"reward": 100, "reviewer": keyID(judge)}, 0))
		return id
	}
	claim := func(k ed25519.PrivateKey, id string) Command {
		return workCommand(s, k, Command{Operation: "work.claim", MessageID: id, TTL: 600})
	}
	// The reviewer names puppet's key as its own; admirer names the
	// reviewer's key as its own. Neither may claim, alone or with a result.
	run(t, s, linkCommand(judge, "identity.link", "ed25519", pubKey(puppet)))
	run(t, s, linkCommand(admirer, "identity.link", "ed25519", pubKey(judge)))
	id := reviewed()
	for name, k := range map[string]ed25519.PrivateKey{"the reviewer": judge, "the reviewer's linked key": puppet, "a key naming the reviewer's": admirer} {
		if msg := failsWith(t, s, claim(k, id), "work_forbidden"); msg != "The reviewer cannot claim work it reviews." {
			t.Errorf("%s: %q", name, msg)
		}
		result := workResult(t, s, k, id, "lobby")
		fails(t, s, workCommand(s, k, Command{Operation: "work.claim", MessageID: id, Target: result}), "work_forbidden")
	}
	if w := getTestWork(t, s, id); w.State != "open" {
		t.Fatalf("a refused claim changed the work: %s", w.State)
	}

	// A link made after the claim: the submit is refused.
	id = reviewed()
	ack := run(t, s, claim(late, id)).Data["ack"].(WorkAck)
	run(t, s, linkCommand(judge, "identity.link", "ed25519", pubKey(late)))
	result := workResult(t, s, late, id, "lobby")
	fails(t, s, workCommand(s, late, Command{Operation: "work.submit", MessageID: id, Amount: ack.Fence, Target: result}), "work_forbidden")

	// An unlinked worker claims, submits and is paid as before.
	id = reviewed()
	fence := claimAndSubmit(t, s, honest, id, "lobby")
	run(t, s, workCommand(s, judge, Command{Operation: "work.accept", MessageID: id, Amount: fence}))
	if got := creditIn(t, s, keyID(honest), "remaining"); got != 100 {
		t.Fatalf("the unlinked worker received %d", got)
	}
}

// A result its own reviewer judged is left out of the work record, as a
// worker linked to the requester is: here the link comes after the accept,
// as on results accepted before the claim check (C551).
func TestWorkRecordLeavesOutReviewerLinkedWorker(t *testing.T) {
	s := reputationStore(t)
	owner, judge, puppet, honest := keyFor(246), keyFor(247), keyFor(248), keyFor(249)
	for _, k := range []ed25519.PrivateKey{owner, judge, puppet, honest} {
		register(t, s, k)
	}
	mintCredit(t, s, keyID(owner), allowance.Paid, 1_000_000)
	const reward = 12_000
	for _, k := range []ed25519.PrivateKey{puppet, honest} {
		id := rewardRequest(t, s, owner, "lobby")
		run(t, s, reviewedCreate(s, owner, id, map[string]any{"reward": reward, "reviewer": keyID(judge)}, 0))
		run(t, s, workCommand(s, judge, Command{Operation: "work.accept", MessageID: id, Amount: claimAndSubmit(t, s, k, id, "lobby")}))
	}
	// The reviewer names puppet's key as its own: puppet's accept drops out.
	run(t, s, linkCommand(judge, "identity.link", "ed25519", pubKey(puppet)))
	records, err := workRecords(testContext, s.db, []string{keyID(puppet), keyID(honest), keyID(owner)}, s.now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	if r := records[keyID(puppet)]; r == nil || r.AsWorker.Accepted != 0 || r.AsWorker.Paid != 0 {
		t.Fatalf("the reviewer's linked worker is counted: %+v", r)
	}
	if r := records[keyID(honest)]; r == nil || r.AsWorker.Accepted != 1 || r.AsWorker.Paid != 1 {
		t.Fatalf("the unlinked worker's record: %+v", r)
	}
	if r := records[keyID(owner)]; r == nil || r.AsRequester.Accepted != 1 {
		t.Fatalf("the requester's record: %+v", r)
	}
}
