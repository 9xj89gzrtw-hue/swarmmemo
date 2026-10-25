package board

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"swarmmemo/internal/allowance"
)

// Accepted results in the work record (C360), on the real store, ledger and
// reviews core: work.get lists an ordinary task's accepted result with its
// worker, the requester's rating and the accept's time; a standing task
// lists each accepted result it opened, newest first, with its tier, and
// leaves out rejected, waiting and hidden ones.
func TestWorkGetAcceptedResults(t *testing.T) {
	s := reputationStore(t)
	owner, w1, w2, w3 := keyFor(230), keyFor(231), keyFor(232), keyFor(233)
	run(t, s, signed(w1, Command{Operation: "agent.register", Handle: "c360worker"}))
	requester := keyID(owner)
	mintCredit(t, s, requester, allowance.Paid, 1_000_000)

	// An ordinary task: nothing listed until the accept.
	a := rewardRequest(t, s, owner, "lobby")
	run(t, s, rewardCreate(s, owner, a, 12_000, 0))
	fence := claimAndSubmit(t, s, w1, a, "lobby")
	if got := getTestWork(t, s, a).Results; got != nil {
		t.Fatalf("a submitted task lists accepted results: %+v", got)
	}
	result := getTestWork(t, s, a).ResultID
	res := run(t, s, ratedAccept(t, s, owner, a, fence, keyID(w1), 77, "Good."))
	review := res.Data["review"].(*Receipt).ID
	w := getTestWork(t, s, a)
	if len(w.Results) != 1 {
		t.Fatalf("accepted results: %+v", w.Results)
	}
	got := w.Results[0]
	if got.ResultID != result || got.WorkID != a || got.Worker.ID != keyID(w1) || got.Worker.Handle != "c360worker" || got.Tier != "" ||
		got.Rating == nil || *got.Rating != 77 || got.ReviewID != review || got.AcceptedAt != s.now().Unix() {
		t.Fatalf("accepted result: %+v", got)
	}
	// The JSON names, as /api/work/ID and read_work give them.
	raw, _ := json.Marshal(w)
	for _, want := range []string{`"results":[{"result_id":"` + result + `","work_id":"` + a + `","worker":{"id":"` + keyID(w1) + `"`, `"rating":77`, `"review_id":"` + review + `"`, `"accepted_at":`} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("work JSON lacks %s: %s", want, raw)
		}
	}
	// A hidden result is not listed, as work.get leaves out its result_id.
	if _, err := s.db.Exec("UPDATE events SET hidden=1,hidden_by='room' WHERE id=?", result); err != nil {
		t.Fatal(err)
	}
	if got := getTestWork(t, s, a).Results; got != nil {
		t.Fatalf("a hidden result is listed: %+v", got)
	}

	// A standing task: two accepted (one with a tier, one rated), one
	// rejected, one waiting.
	id := rewardRequest(t, s, owner, "lobby")
	tiers := []any{map[string]any{"name": "bug", "credits": 300}, map[string]any{"name": "bug+fix", "credits": 500}}
	run(t, s, standingCreate(s, owner, id, map[string]any{"seats": 5, "tiers": tiers, "day_max": 10}, 10*86400))
	r1, c1 := standingClaim(t, s, w1, id, nil)
	run(t, s, c1)
	r2, c2 := standingClaim(t, s, w2, id, nil)
	run(t, s, c2)
	r3, c3 := standingClaim(t, s, w3, id, nil)
	run(t, s, c3)
	run(t, s, workWith(s, owner, Command{Operation: "work.accept", MessageID: r1, Amount: 1}, map[string]any{"tier": "bug+fix"}))
	first := s.now().Unix()
	atTime(s, first+60)
	run(t, s, ratedAccept(t, s, owner, r2, 1, keyID(w2), 40, ""))
	run(t, s, workCommand(s, owner, Command{Operation: "work.reject", MessageID: r3, Amount: 1, Reason: "not reproducible"}))
	atTime(s, first+86400)
	_, c4 := standingClaim(t, s, w3, id, nil)
	run(t, s, c4)

	root := getTestWork(t, s, id)
	if len(root.Results) != 2 {
		t.Fatalf("standing results: %+v", root.Results)
	}
	newest, oldest := root.Results[0], root.Results[1]
	if newest.ResultID != r2 || newest.WorkID != r2 || newest.Worker.ID != keyID(w2) || newest.Tier != "bug" ||
		newest.Rating == nil || *newest.Rating != 40 || newest.AcceptedAt != first+60 {
		t.Fatalf("newest standing result: %+v", newest)
	}
	if oldest.ResultID != r1 || oldest.WorkID != r1 || oldest.Worker.ID != keyID(w1) || oldest.Tier != "bug+fix" || oldest.Rating != nil || oldest.ReviewID != "" || oldest.AcceptedAt != first {
		t.Fatalf("oldest standing result: %+v", oldest)
	}
	// The result's own work item lists itself.
	if own := getTestWork(t, s, r1).Results; len(own) != 1 || !reflect.DeepEqual(own[0], oldest) {
		t.Fatalf("the result's own item: %+v", own)
	}
	if own := getTestWork(t, s, r3).Results; own != nil {
		t.Fatalf("a rejected result lists: %+v", own)
	}
	// works.list rows leave it out: work.get only.
	list := run(t, s, Command{Operation: "works.list", Data: `{"schema":1,"standing":"` + id + `"}`}).Data["works"].([]Work)
	for _, item := range list {
		if item.Results != nil {
			t.Fatalf("works.list row carries results: %+v", item)
		}
	}
}
