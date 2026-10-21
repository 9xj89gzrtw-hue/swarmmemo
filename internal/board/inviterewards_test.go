package board

import (
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Invite rewards (inviterewards.go) on the real engine and ledger: an
// invitee's first activation act pays its inviter once, from the grant pool,
// through the funnel flush; the self-dealing checks refuse for good; a cap
// waits for the daily recompute.

type inviteRewardTest struct {
	t     *testing.T
	s     *Store
	clock atomic.Int64
	rooms int
}

func newInviteRewardTest(t *testing.T) *inviteRewardTest {
	t.Helper()
	it := &inviteRewardTest{t: t, s: rewardStore(t)}
	it.clock.Store(testTime)
	it.s.now = func() time.Time { return time.Unix(it.clock.Load(), 0) }
	return it
}

// invite has inviter make a private room and an invite to it; it answers
// the secret and the create answer's data.
func (it *inviteRewardTest) invite(inviter ed25519.PrivateKey) (string, map[string]any) {
	it.t.Helper()
	it.rooms++
	room := "inv-" + string(rune('a'+it.rooms))
	run(it.t, it.s, signedNow(it.s, inviter, Command{Operation: "room.create", Room: room, Visibility: "private"}))
	created := run(it.t, it.s, signedNow(it.s, inviter, Command{Operation: "room.invite.create", Room: room}))
	return room + "." + created.Data["secret"].(string), created.Data
}

// join has a new key accept code, then do an activation act (a task).
func (it *inviteRewardTest) join(invitee ed25519.PrivateKey, code string, act bool) {
	it.t.Helper()
	room, secret, _ := strings.Cut(code, ".")
	run(it.t, it.s, signedNow(it.s, invitee, Command{Operation: "room.invite.accept", Room: room, Data: secret}))
	if act {
		it.task(invitee)
	}
}

func (it *inviteRewardTest) task(key ed25519.PrivateKey) {
	it.t.Helper()
	run(it.t, it.s, workCommand(it.s, key, Command{Operation: "work.create", MessageID: rewardRequest(it.t, it.s, key, "lobby")}))
}

func (it *inviteRewardTest) flush() {
	it.t.Helper()
	if err := it.s.FlushFunnel(testContext); err != nil {
		it.t.Fatal(err)
	}
}

// paid are the invite rewards journalled to account: lines, credits.
func (it *inviteRewardTest) paid(account string) (int64, int64) {
	it.t.Helper()
	var n, credits int64
	if err := it.s.db.QueryRow("SELECT count(*),coalesce(sum(amount),0) FROM ledger_entries WHERE account=? AND kind='grant' AND op=? AND bucket='granted'", account, InviteRewardOp).Scan(&n, &credits); err != nil {
		it.t.Fatal(err)
	}
	return n, credits
}

func (it *inviteRewardTest) decision(invitee string) string {
	it.t.Helper()
	var d string
	if err := it.s.db.QueryRow("SELECT coalesce(group_concat(detail,'|'),'') FROM audit WHERE actor=? AND operation=?", invitee, InviteRewardOp).Scan(&d); err != nil {
		it.t.Fatal(err)
	}
	return d
}

func TestInviteRewardPaysOnceOnActivation(t *testing.T) {
	it := newInviteRewardTest(t)
	s := it.s
	inviter, invitee := keyFor(140), keyFor(141)
	run(t, s, signedNow(s, inviter, Command{Operation: "agent.register"}))
	code, data := it.invite(inviter)
	offer, _ := data["invite_reward"].(map[string]any)
	if offer == nil || offer["credits"] != int64(500) || !strings.Contains(offer["text"].(string), "500 credits") || !strings.Contains(offer["text"].(string), "USDC is not paid automatically") {
		t.Fatalf("create_invite's answer offers %v", data["invite_reward"])
	}

	// Joining alone is no act: nothing is paid.
	it.join(invitee, code, false)
	it.flush()
	if n, _ := it.paid(keyID(inviter)); n != 0 || it.decision(keyID(invitee)) != "" {
		t.Fatal("paid before the invitee acted")
	}
	// The first activation act pays, once, with the public reason.
	it.task(invitee)
	it.flush()
	if n, credits := it.paid(keyID(inviter)); n != 1 || credits != 500 {
		t.Fatalf("paid %d lines, %d credits", n, credits)
	}
	var reason, ref string
	if err := s.db.QueryRow("SELECT detail,public_ref FROM ledger_entries WHERE account=? AND op=?", keyID(inviter), InviteRewardOp).Scan(&reason, &ref); err != nil {
		t.Fatal(err)
	}
	if reason != "invite reward: "+keyID(invitee)+" activated" || ref != keyID(invitee) {
		t.Fatalf("ledger line %q ref %q", reason, ref)
	}
	// More acts, flushes and the daily recompute never pay again.
	it.task(invitee)
	it.flush()
	if _, err := s.FunnelRecompute(testContext); err != nil {
		t.Fatal(err)
	}
	if n, _ := it.paid(keyID(inviter)); n != 1 || it.decision(keyID(invitee)) != "paid 500 credits" {
		t.Fatalf("paid %d times, decision %q", n, it.decision(keyID(invitee)))
	}
	// The inviter sees it in journal.get and allowance.get.
	for _, op := range []string{"journal.get", "allowance.get"} {
		res := run(t, s, signedNow(s, inviter, Command{Operation: op}))
		var raw []byte
		if op == "journal.get" {
			raw, _ = json.Marshal(res.Data["briefing"].(map[string]any)["invite_rewards"])
		} else {
			raw, _ = json.Marshal(res.Data["invite_rewards"])
		}
		if !strings.Contains(string(raw), `"credits":500`) || !strings.Contains(string(raw), keyID(invitee)) {
			t.Fatalf("%s invite_rewards %s", op, raw)
		}
	}
	// The capabilities name the amount and the caps.
	caps := s.InviteRewardsCapabilities(testContext)
	if caps["on"] != true || caps["credits"] != int64(500) || caps["caps"].(map[string]any)["per_inviter_per_day"] != int64(10) {
		t.Fatalf("capabilities %v", caps)
	}
}

func TestInviteRewardSelfDealingNotPaid(t *testing.T) {
	it := newInviteRewardTest(t)
	s := it.s
	inviter := keyFor(150)
	run(t, s, signedNow(s, inviter, Command{Operation: "agent.register"}))

	// One network: both wrote from the same /24.
	netInvitee := keyFor(151)
	code, _ := it.invite(inviter)
	it.join(netInvitee, code, false)
	for _, acct := range []string{keyID(inviter), keyID(netInvitee)} {
		if _, err := s.db.Exec("INSERT INTO write_signals(created_at,operation,account,via,hash_key,ip_hash_24) VALUES(?,'post',?,'http',?,'net-1')", testTime, acct, s.signals.id); err != nil {
			t.Fatal(err)
		}
	}
	it.task(netInvitee)
	it.flush()
	if d := it.decision(keyID(netInvitee)); d != "not paid: same_network" {
		t.Fatalf("shared network decided %q", d)
	}

	// An operator account invited.
	opInvitee := keyFor(152)
	code, _ = it.invite(inviter)
	it.join(opInvitee, code, false)
	if _, err := s.FunnelExclude(testContext, keyID(opInvitee), true); err != nil {
		t.Fatal(err)
	}
	it.task(opInvitee)
	it.flush()
	if d := it.decision(keyID(opInvitee)); d != "not paid: operator_account" {
		t.Fatalf("operator invitee decided %q", d)
	}

	// One saturation root: both prove one domain, and the trust run roots them there.
	rootInvitee := keyFor(153)
	code, _ = it.invite(inviter)
	it.join(rootInvitee, code, false)
	setStanding(t, s, map[string]int64{keyID(inviter): 100, keyID(rootInvitee): 100})
	if _, err := s.db.Exec("UPDATE trust_scores SET root='domain:acme.org' WHERE account IN (?,?)", keyID(inviter), keyID(rootInvitee)); err != nil {
		t.Fatal(err)
	}
	it.task(rootInvitee)
	it.flush()
	if d := it.decision(keyID(rootInvitee)); d != "not paid: same_root" {
		t.Fatalf("same root decided %q", d)
	}
	if n, _ := it.paid(keyID(inviter)); n != 0 {
		t.Fatal("a self-dealing invite was paid")
	}

	// A key that registered before it accepted, on another day, is no invitee.
	old := keyFor(154)
	run(t, s, signedNow(s, old, Command{Operation: "agent.register"}))
	it.clock.Add(2 * 86400)
	code, _ = it.invite(inviter)
	it.join(old, code, true)
	it.flush()
	if d := it.decision(keyID(old)); d != "" {
		t.Fatalf("an existing agent's invite decided %q", d)
	}
}

func TestInviteRewardCapWaits(t *testing.T) {
	it := newInviteRewardTest(t)
	s := it.s
	if _, err := s.SetAllowanceParams(testContext, InviteRewardsParamsNamespace, []byte(`{"schema":1,"enabled":true,"credits":200,"per_inviter_per_day":1,"daily_credits":20000,"network_days":30}`), "cap test", 0); err != nil {
		t.Fatal(err)
	}
	inviter := keyFor(160)
	run(t, s, signedNow(s, inviter, Command{Operation: "agent.register"}))
	a, b := keyFor(161), keyFor(162)
	codeA, _ := it.invite(inviter)
	codeB, _ := it.invite(inviter)
	it.join(a, codeA, true)
	it.join(b, codeB, true)
	it.flush()
	if n, credits := it.paid(keyID(inviter)); n != 1 || credits != 200 {
		t.Fatalf("day one paid %d lines, %d credits", n, credits)
	}
	// The second waits, undecided, and the next day's recompute pays it.
	it.clock.Add(86400)
	if _, err := s.FunnelRecompute(testContext); err != nil {
		t.Fatal(err)
	}
	if n, _ := it.paid(keyID(inviter)); n != 2 {
		t.Fatalf("the waiting reward was not paid the next day: %d", n)
	}
	// Past the activation window and the retry days, nothing is decided.
	if _, err := s.SetAllowanceParams(testContext, InviteRewardsParamsNamespace, []byte(`{"schema":1,"enabled":false,"credits":200,"per_inviter_per_day":1,"daily_credits":20000,"network_days":30}`), "pause", 0); err != nil {
		t.Fatal(err)
	}
	if caps := s.InviteRewardsCapabilities(testContext); caps["on"] != false || caps["off"] != "paused" {
		t.Fatalf("paused capabilities %v", caps)
	}
}

func TestInviteRewardsParams(t *testing.T) {
	good, _ := json.Marshal(defaultInviteRewardsParams())
	if _, err := parseInviteRewardsParams(good); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{`{}`, `{"schema":1,"enabled":true,"credits":0,"per_inviter_per_day":10,"daily_credits":1,"network_days":30}`,
		`{"schema":1,"enabled":true,"credits":500,"per_inviter_per_day":10,"daily_credits":1,"network_days":30,"extra":1}`} {
		if _, err := parseInviteRewardsParams([]byte(bad)); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
}
