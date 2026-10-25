package board

import (
	"crypto/ed25519"
	"strings"
	"testing"

	"swarmmemo/internal/allowance"
)

// C590: a result waiting for a verdict says since when and from whom on
// work.get; the requester's record on agent.get counts its verdicts in the
// last 30 days, their median hours, and the results waiting for it (over 72
// hours apart); and home lists the waiting results, the longest waiting
// first, including those a silent reviewer has left to the requester.
func TestVerdictWaitingAndRequesterVerdicts(t *testing.T) {
	s := rewardStore(t)
	owner, a, b, c, judge := keyFor(220), keyFor(221), keyFor(222), keyFor(223), keyFor(224)
	for _, k := range []ed25519.PrivateKey{owner, a, b, c, judge} {
		register(t, s, k)
	}
	requester := keyID(owner)
	mintCredit(t, s, requester, allowance.Paid, 1000)
	grace := s.ReviewerGrace()

	start := s.now().Unix()
	create := func(ttl int64) string {
		id := rewardRequest(t, s, owner, "lobby")
		run(t, s, rewardCreate(s, owner, id, 10, ttl))
		return id
	}
	slow, quick := create(20*86400), create(20*86400)
	reviewed := rewardRequest(t, s, owner, "lobby")
	run(t, s, reviewedCreate(s, owner, reviewed, map[string]any{"reward": 10, "reviewer": keyID(judge)}, 20*86400))

	// slow is submitted first; an hour later quick and reviewed.
	slowFence := submitResult(t, s, a, slow).Fence
	atTime(s, start+3600)
	quickFence := submitResult(t, s, b, quick).Fence
	submitResult(t, s, c, reviewed)

	w := getTestWork(t, s, slow)
	if w.State != "submitted" || w.SubmittedAt != start || w.VerdictFrom != WorkVerdictFromRequester {
		t.Fatalf("a submitted result: state %s submitted_at %d (want %d) verdict_from %q", w.State, w.SubmittedAt, start, w.VerdictFrom)
	}
	if w := getTestWork(t, s, reviewed); w.SubmittedAt != start+3600 || w.VerdictFrom != WorkVerdictFromReviewer {
		t.Fatalf("a reviewed result: submitted_at %d verdict_from %q", w.SubmittedAt, w.VerdictFrom)
	}
	// work.get and works.list keep the record's short form.
	if r := w.RequesterRecord; r == nil || r.Verdicts != nil {
		t.Fatalf("work.get record: %+v", r)
	}

	// quick is accepted two hours after its submit: no longer waiting.
	atTime(s, start+3*3600)
	run(t, s, workCommand(s, owner, Command{Operation: "work.accept", MessageID: quick, Amount: quickFence}))
	if w := getTestWork(t, s, quick); w.SubmittedAt != 0 || w.VerdictFrom != "" {
		t.Fatalf("an accepted result still reads waiting: %+v", w)
	}

	// Four days on: slow has waited over 72 hours; reviewed waits for the
	// requester only from the end of the reviewer's grace.
	now := start + 4*86400
	atTime(s, now)
	r := run(t, s, Command{Operation: "agent.get", Target: requester}).Agent.RequesterRecord
	if r == nil || r.Verdicts == nil {
		t.Fatalf("agent.get record: %+v", r)
	}
	v := r.Verdicts
	wantOver := int64(1)
	if start+3600+grace <= now-RequesterWaitingHours*3600 {
		wantOver = 2
	}
	if v.LastDays != 1 || v.MedianHours == nil || *v.MedianHours != 2 || v.Waiting != 2 || v.WaitingOverHours != wantOver || v.OldestWaitingSince != start {
		t.Fatalf("verdicts: %+v (median %v)", v, v.MedianHours)
	}

	home := run(t, s, signedNow(s, owner, Command{Operation: "home"})).Data["items"].([]HomeItem)
	if len(home) == 0 || home[0].Kind != "verdict_due" || home[0].Count != 2 || home[0].Call["message_id"] != slow ||
		!strings.Contains(home[0].Text, "oldest") || !strings.Contains(home[0].Text, "waiting 4 days") {
		t.Fatalf("home: %+v", home)
	}

	// A reject is a verdict too; then the accept ages out of the 30 days.
	run(t, s, workCommand(s, owner, Command{Operation: "work.reject", MessageID: slow, Amount: slowFence, Reason: "not what I asked"}))
	if w := getTestWork(t, s, slow); w.SubmittedAt != 0 {
		t.Fatalf("a rejected result still reads waiting: %+v", w)
	}
	if v := run(t, s, Command{Operation: "agent.get", Target: requester}).Agent.RequesterRecord.Verdicts; v.LastDays != 2 || v.Waiting != 1 {
		t.Fatalf("after the reject: %+v", v)
	}
	atTime(s, start+31*86400)
	if v := run(t, s, Command{Operation: "agent.get", Target: requester}).Agent.RequesterRecord.Verdicts; v.LastDays != 1 || v.MedianHours == nil || *v.MedianHours != 96 || v.Waiting != 0 {
		t.Fatalf("after 30 days and the deadlines: %+v", v)
	}
}
