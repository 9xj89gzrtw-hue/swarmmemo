package board

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"
)

// C541: unprompted repeat paid use. Bounty hunters (a paid call within 7
// days after their own claim or submit, or the accept of a work they hold)
// count only without the filter; genuine payers count in both; free,
// failed, out-of-window, operator and burst calls never count.
func TestFunnelRepeatPaid(t *testing.T) {
	s := openTest(t, Config{})
	now := testTime + 12*3600
	s.now = func() time.Time { return time.Unix(now, 0) }
	today := now / 86400
	at := func(daysAgo, sec int64) int64 { return (today-daysAgo)*86400 + sec }
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := s.db.Exec(q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	for _, a := range []string{"h1", "h2", "h3", "g1", "g2", "req"} {
		exec("INSERT INTO identities(id,public_key,account,created_at,last_seen) VALUES(?,?,?,1,1)", "id-"+a, "pk-"+a, a)
	}
	exec("INSERT INTO meta(key,value) VALUES(?,?)", metaFunnelExclude, `["op"]`)
	burst, _ := json.Marshal(BurstResult{Clusters: []BurstCluster{{ID: 1, Members: []BurstMember{{Account: "b1"}}}}})
	exec("INSERT INTO meta(key,value) VALUES(?,?)", metaFunnelBurst, string(burst))
	n := 0
	work := func(worker string, transitions ...[2]any) {
		t.Helper()
		n++
		id := run(t, s, signed(keyFor(byte(200+n)), Command{Operation: "post", Text: fmt.Sprintf("bounty %d", n), RequestID: randomID(), Timestamp: now})).Receipt.ID
		exec("INSERT INTO works(id,requester,title,capabilities,state,generation,created_at,updated_at,deadline,worker) VALUES(?,'req','t','[]','accepted','g',1,1,?,?)", id, now+86400, worker)
		for i, tr := range transitions {
			op := tr[0].(string)
			author := "id-" + worker
			if op == "work.accept" {
				author = "id-req"
			}
			exec("INSERT INTO work_transitions(work_id,sequence,operation,author,public_key,signature,payload,accepted_at,fence,generation,state) VALUES(?,?,?,?,'k','s','{}',?,0,'g','accepted')", id, i+1, op, author, tr[1])
		}
	}
	work("h1", [2]any{"work.claim", at(3, 100)})
	work("h2", [2]any{"work.submit", at(1, 100)})
	work("h3", [2]any{"work.claim", at(20, 100)}, [2]any{"work.accept", at(2, 100)})
	work("g2", [2]any{"work.claim", at(14, 100)}) // 10 days before its first call
	var room string
	if err := s.db.QueryRow("SELECT room FROM events WHERE text='bounty 1'").Scan(&room); err != nil {
		t.Fatal(err)
	}
	exec("INSERT INTO delegations(child_id,public_key,parent_account,issuer_id,issuer_key,room,operations,generation,created_at,expires_at,ceiling_bytes,payload,signature,proof) VALUES('child-g2','pk-child-g2','g2','id-g2','pk-g2',?,'[]','g',1,?,1000,'{}','s','p')", room, now+86400)
	sc := 0
	service := func(account, service, state string, cost int64, t0 int64) {
		sc++
		exec("INSERT INTO service_calls(id,account,service,method,request_key,hold_id,resource,cost,state,prices_version,created_at) VALUES(?,?,?,'call',?,?,'credit',?,?,1,?)", fmt.Sprintf("sc%d", sc), account, service, fmt.Sprintf("rk%d", sc), fmt.Sprintf("h%d", sc), cost, state, t0)
	}
	offering := func(caller string, settled int64) {
		sc++
		id := fmt.Sprintf("oc%d", sc)
		exec(`INSERT INTO offering_calls(id,account,name,rev,caller,payer,amount,network,asset,pay_to,input,input_sha256,auth_nonce,quote_hash,valid_before,state,poll_hash,created_at,claim_by,settled_at)
VALUES(?,'seller','oracle',1,?,'0xpayer',1000,'eip155:8453','usdc','0xpay','{}','x',?,'q',1,'answered','p',?,?,?)`, id, caller, id, settled, settled, settled)
	}
	service("h1", "x402", "done", 5, at(2, 200)) // after its claim: prompted
	service("h1", "x402", "done", 5, at(1, 200))
	service("h2", "notary", "done", 1, at(6, 200)) // before its submit: unprompted
	service("h2", "notary", "done", 1, at(1, 200)) // after: prompted
	offering("id-h3", at(0, 200))                  // after the accept of its work: prompted
	service("g1", "notary", "done", 1, at(5, 200))
	service("g1", "notary", "done", 1, at(2, 200))
	service("g1", "x402", "done", 5, at(2, 300))
	service("g1", "notary", "done", 1, at(8, 200)) // before the window
	offering("id-g2", at(4, 200))
	offering("child-g2", at(0, 300))                 // a delegated key's call is its parent's
	service("g3", "notary", "done", 0, at(1, 200))   // free
	service("g3", "notary", "failed", 3, at(2, 200)) // did not run
	service("op", "notary", "done", 1, at(1, 200))   // operator
	service("op", "notary", "done", 1, at(2, 200))
	service("b1", "x402", "done", 5, at(1, 200)) // burst member

	kpi, err := s.FunnelKPIFor(testContext, 7)
	if err != nil {
		t.Fatal(err)
	}
	r := kpi.RepeatPaid
	c := func(p, rp, calls int) RepeatPaidCounts {
		return RepeatPaidCounts{Payers: p, RepeatPayers: rp, Calls: calls}
	}
	want := map[string]RepeatPaidPair{
		"total":    {Unprompted: c(3, 2, 6), All: c(5, 4, 10)},
		"service":  {Unprompted: c(2, 1, 3), All: c(2, 2, 4)},
		"x402":     {Unprompted: c(1, 0, 1), All: c(2, 1, 3)},
		"offering": {Unprompted: c(1, 1, 2), All: c(2, 1, 3)},
	}
	got := map[string]RepeatPaidPair{"total": r.Total}
	for k, v := range r.ByKind {
		got[k] = v
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s: got %+v, want %+v", k, got[k], w)
		}
	}
	if len(r.ByKind) != 3 || r.BurstPayersLeftOut != 1 || r.LookbackDays != 7 || r.MinDays != 2 || r.From != at(6, 0) || r.To != now {
		t.Errorf("window: %+v", r)
	}
	// The report over the same range counts the same.
	rep, err := s.FunnelReport(testContext, FunnelQuery{From: at(6, 0), To: now})
	if err != nil {
		t.Fatal(err)
	}
	if rep.RepeatPaid.Total != r.Total || rep.RepeatPaid.ByKind["offering"] != r.ByKind["offering"] {
		t.Errorf("report: %+v, kpi %+v", rep.RepeatPaid, r)
	}
	// Aggregates only: the JSON names no account.
	raw, _ := json.Marshal(r)
	for _, a := range []string{"h1", "g1", "g2", "b1", "op"} {
		if strings.Contains(string(raw), strconv.Quote(a)) {
			t.Errorf("repeat_paid names %s: %s", a, raw)
		}
	}
}
