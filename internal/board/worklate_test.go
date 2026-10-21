package board

import (
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"swarmmemo/internal/allowance"
)

// Verdicts due (worklate.go, C511) on the real store, ledger and inbox log:
// the submit's entry tells the decider by when and how, one reminder comes
// a day before the deadline, and the requester may still accept late,
// paying the reward again from its own credits.

type lateTest struct {
	t     *testing.T
	s     *Store
	clock atomic.Int64
}

func newLateTest(t *testing.T) *lateTest {
	t.Helper()
	if _, _, ok := ledgerTestOverride(); ok {
		t.Skip("the ledger mode is overridden for the whole suite")
	}
	c := rewardConfig()
	c.Features.InboxEntries = InboxRead
	lt := &lateTest{t: t, s: openTest(t, c)}
	t.Cleanup(lt.s.stopServices)
	setRewardParams(t, lt.s)
	lt.clock.Store(testTime)
	lt.s.now = func() time.Time { return time.Unix(lt.clock.Load(), 0) }
	return lt
}

func (lt *lateTest) sweep() {
	lt.t.Helper()
	if _, err := lt.s.SweepAllowance(testContext); err != nil {
		lt.t.Fatal(err)
	}
}

// entries are key's own inbox entries about work id, from the start.
func (lt *lateTest) entries(key ed25519.PrivateKey, id string) []UpdateEntry {
	lt.t.Helper()
	r := run(lt.t, lt.s, signedNow(lt.s, key, Command{Operation: "updates.get", Target: keyID(key), Cursor: "start"}))
	var out []UpdateEntry
	for _, e := range r.Data["entries"].([]UpdateEntry) {
		if e.Kind == inboxWork && strings.HasPrefix(e.Subject, id+"@") {
			out = append(out, e)
		}
	}
	return out
}

type lateDetail struct {
	State    string `json:"state"`
	Role     string `json:"role"`
	DecideBy int64  `json:"decide_by"`
	Next     string `json:"next"`
	Reminder bool   `json:"reminder"`
}

func detailOf(t *testing.T, e UpdateEntry) lateDetail {
	t.Helper()
	var d lateDetail
	if err := json.Unmarshal(e.Detail, &d); err != nil {
		t.Fatalf("detail %s: %v", e.Detail, err)
	}
	return d
}

func (lt *lateTest) accept(key ed25519.PrivateKey, id string, fence int64) Command {
	return workCommand(lt.s, key, Command{Operation: "work.accept", MessageID: id, Amount: fence})
}

func TestWorkVerdictDueNoticeAndReminder(t *testing.T) {
	lt := newLateTest(t)
	s := lt.s
	owner, worker := keyFor(150), keyFor(151)
	id := createTestWork(t, s, owner, "lobby", "request", 3*86400)
	fence := claimAndSubmit(t, s, worker, id, "lobby")
	deadline := getTestWork(t, s, id).Deadline

	// The submit's entry waits for the requester's verdict and says by when;
	// the claim's before it was news.
	list := lt.entries(owner, id)
	if len(list) != 2 || list[0].NeedsAnswer || !list[1].NeedsAnswer {
		t.Fatalf("the requester's entries: %+v", list)
	}
	if d := detailOf(t, list[1]); d.State != "submitted" || d.DecideBy != deadline || d.Next != WorkVerdictNext || d.Reminder {
		t.Fatalf("submit entry detail: %+v", d)
	}
	// The worker's entry is news, not a question.
	for _, e := range lt.entries(worker, id) {
		if e.NeedsAnswer || detailOf(t, e).DecideBy != 0 {
			t.Fatalf("the worker's entry: %+v", e)
		}
	}

	// No reminder before it is due; then exactly one, however often the
	// sweeper runs.
	lt.sweep()
	if n := sqlCount(t, s, "SELECT count(*) FROM inbox_entries WHERE subject=?", id+workReminderSuffix); n != 0 {
		t.Fatalf("%d reminders before one was due", n)
	}
	lt.clock.Store(deadline - WorkVerdictReminderLead + 60)
	// A result submitted within the last day gets none: its submit is the notice.
	late := createTestWork(t, s, owner, "lobby", "request", 3600)
	claimAndSubmit(t, s, worker, late, "lobby")
	lt.sweep()
	lt.sweep()
	list = lt.entries(owner, id)
	if len(list) != 3 || list[2].Subject != id+workReminderSuffix || !list[2].NeedsAnswer {
		t.Fatalf("after the reminder: %+v", list)
	}
	if d := detailOf(t, list[2]); !d.Reminder || d.DecideBy != deadline || d.Next != WorkVerdictNext || d.Role != "reviewer" {
		t.Fatalf("reminder detail: %+v", d)
	}
	if n := sqlCount(t, s, "SELECT count(*) FROM inbox_entries WHERE subject=?", id+workReminderSuffix); n != 1 {
		t.Fatalf("%d reminder entries, want one (the requester's)", n)
	}
	if n := sqlCount(t, s, "SELECT count(*) FROM inbox_entries WHERE subject=?", late+workReminderSuffix); n != 0 {
		t.Fatalf("a result submitted within the lead was reminded of (%d)", n)
	}

	// The verdict closes the submit's entry and the reminder alike.
	run(t, s, lt.accept(owner, id, fence))
	for _, e := range lt.entries(owner, id) {
		if e.NeedsAnswer && e.Disposition != "closure" {
			t.Fatalf("open after the verdict: %+v", e)
		}
	}
}

func TestWorkLateAccept(t *testing.T) {
	lt := newLateTest(t)
	s := lt.s
	owner, worker := keyFor(152), keyFor(153)
	requester, payee := keyID(owner), keyID(worker)
	mintCredit(t, s, requester, allowance.Paid, 500)
	rewarded := rewardRequest(t, s, owner, "lobby")
	run(t, s, rewardCreate(s, owner, rewarded, 100, 3600))
	rewardedFence := claimAndSubmit(t, s, worker, rewarded, "lobby")
	edited := createTestWork(t, s, owner, "lobby", "request", 3600)
	editedFence := claimAndSubmit(t, s, worker, edited, "lobby")
	plain := createTestWork(t, s, owner, "lobby", "request", 3600)
	plainFence := claimAndSubmit(t, s, worker, plain, "lobby")
	closed := createTestWork(t, s, owner, "lobby", "request", 3600)
	closedFence := claimAndSubmit(t, s, worker, closed, "lobby")
	deadline := getTestWork(t, s, rewarded).Deadline

	// The deadline passes with every result undecided: the sweeper gives the
	// reward back to the requester, requester_lapsed.
	lt.clock.Store(deadline + 60)
	lt.sweep()
	w := getTestWork(t, s, rewarded)
	if w.State != "expired" || w.Reward.State != "released" || w.Reward.Reason != "requester_lapsed" {
		t.Fatalf("at the deadline: %s %+v", w.State, w.Reward)
	}
	if r := w.RequesterRecord; r == nil || r.UnpaidLapsed != 1 {
		t.Fatalf("record at the deadline: %+v", r)
	}

	// The journal and home list what may still be accepted.
	j := run(t, s, signedNow(s, owner, Command{Operation: "journal.get", Limit: 1}))
	items := j.Data["briefing"].(map[string]any)["open_work"].(map[string]any)["work"].(map[string]any)["items"].([]map[string]any)
	if len(items) != 4 || !strings.Contains(items[0]["next"].(string), "late accept") {
		t.Fatalf("journal open work: %+v", items)
	}
	home := run(t, s, signedNow(s, owner, Command{Operation: "home"})).Data["items"].([]HomeItem)
	if len(home) == 0 || home[0].Kind != "verdict_due" || home[0].Count != 4 || !strings.Contains(home[0].Text, "past its deadline") {
		t.Fatalf("home: %+v", home)
	}

	// Only the requester accepts, and only accepts.
	fails(t, s, lt.accept(worker, plain, plainFence), "work_forbidden")
	fails(t, s, workCommand(s, owner, Command{Operation: "work.reject", MessageID: plain, Amount: plainFence, Reason: "too late"}), "work_state_conflict")
	// Only the result exactly as submitted.
	result := getTestWork(t, s, edited).ResultID
	run(t, s, signedNow(s, worker, Command{Operation: "post", Room: "lobby", ReplyTo: edited, Text: "Human-reviewed result reference, revised", Data: `{"schema":1,"supersedes":"` + result + `"}`}))
	fails(t, s, lt.accept(owner, edited, editedFence), "work_state_conflict")

	// Without a reward, a late accept is an accept.
	ack := run(t, s, lt.accept(owner, plain, plainFence)).Data["ack"].(WorkAck)
	if ack.State != "accepted" || ack.Note != workLateNote(0) || getTestWork(t, s, plain).State != "accepted" {
		t.Fatalf("late accept: %+v", ack)
	}

	// The released reward is paid again from the requester's credits: 100
	// and a transfer fee of 2. Another task holds all but 101 of them.
	spare := creditIn(t, s, requester, "remaining") - creditIn(t, s, requester, "held")
	run(t, s, rewardCreate(s, owner, rewardRequest(t, s, owner, "lobby"), spare-2-101, 3600))
	fails(t, s, lt.accept(owner, rewarded, rewardedFence), "late_accept_needs_credits")
	if w := getTestWork(t, s, rewarded); w.State != "expired" || w.Reward.State != "released" || creditIn(t, s, payee, "remaining") != 0 {
		t.Fatalf("a refused late accept changed something: %s %+v", w.State, w.Reward)
	}
	mintCredit(t, s, requester, allowance.Paid, 1)
	ack = run(t, s, lt.accept(owner, rewarded, rewardedFence)).Data["ack"].(WorkAck)
	if !strings.HasPrefix(ack.Note, workLateNote(100)) {
		t.Fatalf("late accept note: %q", ack.Note)
	}
	w = getTestWork(t, s, rewarded)
	if w.State != "accepted" || w.Reward.State != "paid" || w.Reward.Reason != "" || w.Reward.Fee != 4 || creditIn(t, s, payee, "remaining") != 100 || creditIn(t, s, requester, "held") != spare-2-101 {
		t.Fatalf("after the late accept: %s %+v, worker %d", w.State, w.Reward, creditIn(t, s, payee, "remaining"))
	}
	if r := w.RequesterRecord; r.Paid != 1 || r.UnpaidLapsed != 0 {
		t.Fatalf("record after the late accept: %+v", r)
	}
	// Paid once: the accept is final.
	fails(t, s, lt.accept(owner, rewarded, rewardedFence), "work_state_conflict")

	// The late accept closes WORK_LATE_ACCEPT after the deadline.
	lt.clock.Store(deadline + s.WorkLateAccept())
	fails(t, s, lt.accept(owner, closed, closedFence), "work_state_conflict")
}
