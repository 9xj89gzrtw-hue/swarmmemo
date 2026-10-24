package board

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func pubB64(key ed25519.PrivateKey) string {
	return base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
}

func deviceTestStore(t *testing.T) *Store {
	t.Helper()
	return openTest(t, Config{Features: Features{InboxEntries: InboxRead}})
}

// deviceCode is a fresh device.request's code (the answer shows it once).
func deviceCode(t *testing.T, s *Store, device ed25519.PrivateKey, label string) string {
	t.Helper()
	r := run(t, s, signedNow(s, device, Command{Operation: "device.request", Data: `{"schema":1,"label":"` + label + `"}`}))
	code, _ := r.Data["code"].(string)
	if len(code) != 9 || code[4] != '-' || !strings.HasSuffix(r.Data["link"].(string), "/me#link="+strings.ReplaceAll(code, "-", "")) {
		t.Fatalf("device.request %v", r.Data)
	}
	return code
}

// approveDevice is the main key's device.add without a proof: the approval
// kept on the request.
func approveDevice(t *testing.T, s *Store, main, device ed25519.PrivateKey, code string) Command {
	t.Helper()
	c := signedNow(s, main, Command{Operation: "device.add", Target: pubB64(device), Data: `{"schema":1,"label":"phone","code_sha256":"` + DeviceCodeSHA256(code) + `"}`})
	r := run(t, s, c)
	if r.Data["state"] != "approved" || r.Receipt != nil {
		t.Fatalf("approval %v", r.Data)
	}
	return c
}

// confirmDevice is the new device's half: it reads the approval and sends
// the stored command with its proof.
func confirmDevice(t *testing.T, s *Store, device ed25519.PrivateKey, code string) Result {
	t.Helper()
	read := run(t, s, signedNow(s, device, Command{Operation: "device.request.get", Data: `{"schema":1,"code":"` + code + `"}`}))
	approval, ok := read.Data["approval"].(map[string]any)
	if !ok {
		t.Fatalf("no approval for the device: %v", read.Data)
	}
	cmd := approval["command"].(Command)
	if cmd.Target != pubB64(device) || approval["canonical"] != string(Canonical("swarmmemo.com", cmd)) {
		t.Fatalf("approval names another key %v", approval)
	}
	cmd.Proof = base64.RawURLEncoding.EncodeToString(ed25519.Sign(device, Canonical("swarmmemo.com", cmd)))
	return run(t, s, cmd)
}

func linkDevice(t *testing.T, s *Store, main, device ed25519.PrivateKey) {
	t.Helper()
	code := deviceCode(t, s, device, "phone")
	approveDevice(t, s, main, device, code)
	if r := confirmDevice(t, s, device, code); r.Data["device"] != keyID(device) {
		t.Fatalf("link %v", r.Data)
	}
}

func TestDeviceLinkHappyPath(t *testing.T) {
	s := deviceTestStore(t)
	main, phone := keyFor(201), keyFor(202)
	run(t, s, signed(main, Command{Operation: "agent.register", Handle: "hugo"}))
	code := deviceCode(t, s, phone, "Chrome on Windows")
	// The request key is no agent yet.
	if n := sqlCount(t, s, "SELECT count(*) FROM identities WHERE id=?", keyID(phone)); n != 0 {
		t.Fatalf("device.request made an agent: %d", n)
	}
	// Only the code's hash is stored.
	if n := sqlCount(t, s, "SELECT count(*) FROM device_requests WHERE code_sha256=?", DeviceCodeSHA256(code)); n != 1 {
		t.Fatal("request not stored by its hash")
	}
	if n := sqlCount(t, s, "SELECT count(*) FROM requests WHERE result LIKE ?", "%"+strings.ReplaceAll(code, "-", "")+"%"); n != 0 {
		t.Fatal("the code is kept in a stored receipt")
	}
	look := run(t, s, signed(main, Command{Operation: "device.request.get", Data: `{"schema":1,"code":"` + strings.ToLower(code) + `"}`})).Data
	if look["label"] != "Chrome on Windows" || look["device"] != keyID(phone) || look["approval"] != nil || len(look["match"].([]string)) != 4 {
		t.Fatalf("approver's look %v", look)
	}
	approveDevice(t, s, main, phone, code)
	r := confirmDevice(t, s, phone, code).Data
	if r["account"] != keyID(main) || r["handle"] != "hugo" || r["label"] != "phone" || r["held_until"] != testTime+DeviceHoldSeconds {
		t.Fatalf("device.add %v", r)
	}
	// The device posts as the same agent, and the post verifies on its own key.
	receipt := run(t, s, signed(phone, Command{Operation: "post", Room: "lobby", Text: "from my phone"})).Receipt
	msg := run(t, s, Command{Operation: "message.get", MessageID: receipt.ID}).Messages[0]
	if msg.Handle != "hugo" || msg.AuthorHandle != "hugo" || msg.Author != keyID(phone) || msg.PublicKey != pubB64(phone) {
		t.Fatalf("device post %+v", msg)
	}
	if n := sqlCount(t, s, "SELECT count(*) FROM events WHERE id=? AND account=?", receipt.ID, keyID(main)); n != 1 {
		t.Fatal("the device's post is not the account's")
	}
	sig, _ := base64.RawURLEncoding.DecodeString(msg.Signature)
	if !ed25519.Verify(phone.Public().(ed25519.PublicKey), []byte(msg.SignedPayload), sig) {
		t.Fatal("the post does not verify on the device key")
	}
	// The directory, agent.get and the account count one agent.
	if got := run(t, s, Command{Operation: "agent.get", Target: keyID(phone)}).Agent; got.ID != keyID(main) || got.Handle != "hugo" {
		t.Fatalf("agent.get of the device %+v", got)
	}
	if n := len(run(t, s, Command{Operation: "agents.list", Kind: "new"}).Agents); n != 1 {
		t.Fatalf("directory lists %d agents", n)
	}
	// Both keys read the same inbox, which says a device was linked.
	for _, key := range []ed25519.PrivateKey{main, phone} {
		up := run(t, s, signed(key, Command{Operation: "updates.get", Target: keyID(key), Limit: PageMax}))
		entries, _ := up.Data["entries"].([]UpdateEntry)
		found := false
		for _, e := range entries {
			found = found || e.Kind == inboxDevice && e.Actor == keyID(phone) && strings.Contains(string(e.Detail), `"change":"added"`)
		}
		if !found {
			t.Fatalf("no device notice in the inbox of %s: %+v", keyID(key), up.Data)
		}
	}
	// The owner's list, and the public one without labels.
	own := run(t, s, signed(phone, Command{Operation: "devices.list"})).Data["devices"].([]DeviceView)
	if len(own) != 2 || own[0].Role != "primary" || own[1].Label != "phone" || !own[1].ThisDevice || own[1].HeldUntil == 0 {
		t.Fatalf("own devices %+v", own)
	}
	public := run(t, s, Command{Operation: "devices.list", Target: "hugo"}).Data["devices"].([]DeviceView)
	if len(public) != 2 || public[1].Label != "" || public[1].LastSeen != 0 || public[1].PublicKey != pubB64(phone) {
		t.Fatalf("public devices %+v", public)
	}
	// The breaker ran, as on a rotation.
	if n := sqlCount(t, s, "SELECT count(*) FROM account_breakers WHERE reason='device.add' AND account=?", keyID(main)); n != 1 && s.config.Features.Ledger != LedgerOff {
		t.Fatalf("%d breakers", n)
	}
	// The record carries the binding.
	if _, err := s.SignCheckpoint(testContext); err != nil {
		t.Fatal(err)
	}
	rec, err := s.ReadLogRecord(testContext, keyID(main))
	if err != nil {
		t.Fatal(err)
	}
	var keys []RecordKey
	raw, _ := json.Marshal(rec.Record.Keys)
	_ = json.Unmarshal(raw, &keys)
	if len(keys) != 2 || keys[1].Role != "device" || rec.Record.Agent != keyID(main) {
		t.Fatalf("record keys %+v agent %s", keys, rec.Record.Agent)
	}
}

func TestDeviceCodeIsOneTimeAndExpires(t *testing.T) {
	s := deviceTestStore(t)
	main, phone, other := keyFor(211), keyFor(212), keyFor(213)
	register(t, s, main)
	code := deviceCode(t, s, phone, "phone")
	fails(t, s, signedNow(s, main, Command{Operation: "device.request.get", Data: `{"schema":1,"code":"ZZZZ-ZZZZ"}`}), "device_request_not_found")
	fails(t, s, signedNow(s, main, Command{Operation: "device.request.get", Data: `{"schema":1,"code":"short"}`}), "invalid_device_data")
	// An approval for another key than the request's is refused.
	fails(t, s, signedNow(s, main, Command{Operation: "device.add", Target: pubB64(other), Data: `{"schema":1,"code_sha256":"` + DeviceCodeSHA256(code) + `"}`}), "device_request_not_found")
	approveDevice(t, s, main, phone, code)
	confirmDevice(t, s, phone, code)
	// Used: the code finds nothing, and a second link with it is refused.
	fails(t, s, signedNow(s, main, Command{Operation: "device.request.get", Data: `{"schema":1,"code":"` + code + `"}`}), "device_request_not_found")
	fails(t, s, signedNow(s, main, Command{Operation: "device.add", Target: pubB64(other), Data: `{"schema":1,"code_sha256":"` + DeviceCodeSHA256(code) + `"}`}), "device_request_not_found")

	// An approval by one account is not replaced by another's.
	rival, tablet := keyFor(215), keyFor(216)
	register(t, s, rival)
	code = deviceCode(t, s, tablet, "tablet")
	approveDevice(t, s, main, tablet, code)
	fails(t, s, signedNow(s, rival, Command{Operation: "device.add", Target: pubB64(tablet), Data: `{"schema":1,"code_sha256":"` + DeviceCodeSHA256(code) + `"}`}), "device_request_not_found")
	// The new device polls its own request without spending the network's reads.
	for range DeviceRequestsPerHour + 5 {
		run(t, s, signedNow(s, tablet, Command{Operation: "device.request.get", Data: `{"schema":1,"code":"` + code + `"}`}))
	}

	// A code expires in ten minutes.
	late := keyFor(214)
	code = deviceCode(t, s, late, "laptop")
	s.now = func() time.Time { return time.Unix(testTime+DeviceCodeTTL, 0) }
	fails(t, s, signedNow(s, main, Command{Operation: "device.request.get", Data: `{"schema":1,"code":"` + code + `"}`}), "device_request_expired")
	fails(t, s, signedNow(s, main, Command{Operation: "device.add", Target: pubB64(late), Data: `{"schema":1,"code_sha256":"` + DeviceCodeSHA256(code) + `"}`}), "device_request_expired")

	// Guessing codes runs out of reads.
	s2 := deviceTestStore(t)
	guesser := keyFor(217)
	refused := false
	for i := range DeviceRequestsPerHour + 1 {
		_, err := s2.Execute(testContext, signedNow(s2, guesser, Command{Operation: "device.request.get", Data: `{"schema":1,"code":"` + strings.Repeat(string(deviceCodeAlphabet[i%32]), 8) + `"}`}), "203.0.113.9")
		var e *Error
		refused = refused || errors.As(err, &e) && e.Code == "device_rate_limited"
	}
	if !refused {
		t.Fatal("code reads are not limited")
	}
}

func TestDeviceApprovalNearExpiry(t *testing.T) {
	s := deviceTestStore(t)
	main, phone := keyFor(218), keyFor(219)
	register(t, s, main)
	code := deviceCode(t, s, phone, "phone")
	// Approved a minute before the code expires, confirmed two minutes later.
	s.now = func() time.Time { return time.Unix(testTime+DeviceCodeTTL-60, 0) }
	approveDevice(t, s, main, phone, code)
	s.now = func() time.Time { return time.Unix(testTime+DeviceCodeTTL+60, 0) }
	confirmDevice(t, s, phone, code)
}

func TestDeviceConfirmationIsBound(t *testing.T) {
	s := deviceTestStore(t)
	main, phone, thief := keyFor(221), keyFor(222), keyFor(223)
	register(t, s, main)
	code := deviceCode(t, s, phone, "phone")
	approval := approveDevice(t, s, main, phone, code)
	// Another key reading the code sees no approval to take.
	if r := run(t, s, signedNow(s, thief, Command{Operation: "device.request.get", Data: `{"schema":1,"code":"` + code + `"}`})).Data; r["approval"] != nil {
		t.Fatalf("approval shown to another key %v", r)
	}
	// A proof by another key is refused.
	forged := approval
	forged.Proof = base64.RawURLEncoding.EncodeToString(ed25519.Sign(thief, Canonical("swarmmemo.com", approval)))
	fails(t, s, forged, "invalid_device_proof")
	// A different two-key command (another label) is not the approved one.
	other := signedNow(s, main, Command{Operation: "device.add", Target: pubB64(phone), Data: `{"schema":1,"label":"evil","code_sha256":"` + DeviceCodeSHA256(code) + `"}`})
	other.Proof = base64.RawURLEncoding.EncodeToString(ed25519.Sign(phone, Canonical("swarmmemo.com", other)))
	fails(t, s, other, "device_request_not_approved")
	confirmDevice(t, s, phone, code)
	// The approval sent again is the same command: its receipt, nothing more.
	replay := approval
	replay.Proof = base64.RawURLEncoding.EncodeToString(ed25519.Sign(phone, Canonical("swarmmemo.com", approval)))
	if r := run(t, s, replay); r.Receipt != nil && !r.Receipt.Duplicate {
		t.Fatalf("replay %+v", r)
	}
	if n := sqlCount(t, s, "SELECT count(*) FROM identities WHERE account=? AND role='device'", keyID(main)); n != 1 {
		t.Fatalf("%d devices after a replay", n)
	}

	// The proof must come within five minutes of the approval.
	slow := keyFor(224)
	code = deviceCode(t, s, slow, "slow")
	approval = approveDevice(t, s, main, slow, code)
	s.now = func() time.Time { return time.Unix(testTime+SignatureWindowSeconds+1, 0) }
	approval.Proof = base64.RawURLEncoding.EncodeToString(ed25519.Sign(slow, Canonical("swarmmemo.com", approval)))
	fails(t, s, approval, "stale_signature")
}

func TestDeviceLimitsAndRemoval(t *testing.T) {
	s := deviceTestStore(t)
	main, phone, laptop := keyFor(231), keyFor(232), keyFor(233)
	run(t, s, signed(main, Command{Operation: "agent.register", Handle: "owner"}))
	linkDevice(t, s, main, phone)
	// v1: a device adds no device, rotates nothing and moves no room.
	code := deviceCode(t, s, laptop, "laptop")
	fails(t, s, signedNow(s, phone, Command{Operation: "device.add", Target: pubB64(laptop), Data: `{"schema":1,"code_sha256":"` + DeviceCodeSHA256(code) + `"}`}), "primary_key_required")
	fails(t, s, signedNow(s, phone, Command{Operation: "agent.rotate", Target: pubB64(laptop)}), "primary_key_required")
	// The 24-hour hold: no handle change, transfer or link from the new device.
	fails(t, s, signedNow(s, phone, Command{Operation: "agent.register", Handle: "thief"}), "device_hold")
	fails(t, s, signedNow(s, phone, Command{Operation: "credit.transfer", Target: keyID(laptop), Amount: 10}), "device_hold")
	fails(t, s, signedNow(s, phone, Command{Operation: "identity.link", Data: `{"schema":1,"kind":"url","value":"https://example.com"}`}), "device_hold")
	if r := run(t, s, signedNow(s, phone, Command{Operation: "post", Room: "lobby", Text: "hi", Handle: "other"})).Receipt; r.HandleNotApplied == nil {
		t.Fatal("a held device's post changed the handle")
	}
	s.now = func() time.Time { return time.Unix(testTime+DeviceHoldSeconds, 0) }
	run(t, s, signedNow(s, phone, Command{Operation: "agent.register", Handle: "renamed"}))
	if h, _ := accountHandle(testContext, s.db, keyID(main)); h != "renamed" {
		t.Fatalf("handle %q after a device renamed the account", h)
	}
	// A device removes only itself; the main key removes any.
	linkDevice(t, s, main, laptop)
	fails(t, s, signedNow(s, phone, Command{Operation: "device.revoke", Target: keyID(laptop)}), "primary_key_required")
	run(t, s, signedNow(s, main, Command{Operation: "device.revoke", Target: keyID(laptop)}))
	run(t, s, signedNow(s, phone, Command{Operation: "device.revoke"}))
	// A removed device's later signatures fail, reads and writes alike.
	fails(t, s, signedNow(s, phone, Command{Operation: "post", Room: "lobby", Text: "after removal"}), "key_revoked")
	fails(t, s, signedNow(s, laptop, Command{Operation: "updates.get"}), "key_revoked")
	fails(t, s, signedNow(s, main, Command{Operation: "device.revoke", Target: keyID(phone)}), "device_not_found")
	// The main key is no device.
	fails(t, s, signedNow(s, main, Command{Operation: "device.revoke"}), "invalid_device_data")
	if n := len(run(t, s, signedNow(s, main, Command{Operation: "devices.list"})).Data["devices"].([]DeviceView)); n != 1 {
		t.Fatalf("%d keys listed after removals", n)
	}
	public := run(t, s, Command{Operation: "devices.list", Target: keyID(main)}).Data["devices"].([]DeviceView)
	if len(public) != 3 || public[1].RemovedAt == 0 {
		t.Fatalf("public record of removals %+v", public)
	}
}

func TestDeviceMaxAndFreshKeys(t *testing.T) {
	s := deviceTestStore(t)
	main, other := keyFor(241), keyFor(242)
	register(t, s, main)
	register(t, s, other)
	// An existing agent cannot ask to become a device, nor be added as one.
	fails(t, s, signedNow(s, other, Command{Operation: "device.request"}), "agent_exists")
	add := signedNow(s, main, Command{Operation: "device.add", Target: pubB64(other), Data: `{"schema":1}`})
	add.Proof = base64.RawURLEncoding.EncodeToString(ed25519.Sign(other, Canonical("swarmmemo.com", add)))
	fails(t, s, add, "agent_exists")
	// No proof and no code: refused.
	fails(t, s, signedNow(s, main, Command{Operation: "device.add", Target: pubB64(keyFor(170)), Data: `{"schema":1}`}), "invalid_device_proof")
	// Both keys at hand: a direct link with no code.
	for i := range DeviceMax {
		key := keyFor(byte(150 + i))
		c := signedNow(s, main, Command{Operation: "device.add", Target: pubB64(key), Data: `{"schema":1,"label":"bot"}`})
		c.Proof = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, Canonical("swarmmemo.com", c)))
		run(t, s, c)
	}
	extra := keyFor(170)
	c := signedNow(s, main, Command{Operation: "device.add", Target: pubB64(extra), Data: `{"schema":1}`})
	c.Proof = base64.RawURLEncoding.EncodeToString(ed25519.Sign(extra, Canonical("swarmmemo.com", c)))
	fails(t, s, c, "device_limit")
}

func TestDeviceGrantsDieWithTheDevice(t *testing.T) {
	s := deviceTestStore(t)
	main, phone, worker := keyFor(251), keyFor(252), keyFor(253)
	run(t, s, signed(main, Command{Operation: "post", Room: "lobby", Text: "the room exists"}))
	linkDevice(t, s, main, phone)
	fails(t, s, grantCommand(s, phone, worker, "lobby", 3600, 4096, grantOps()), "device_hold")
	s.now = func() time.Time { return time.Unix(testTime+DeviceHoldSeconds, 0) }
	grant := enroll(t, s, phone, worker, "lobby", 3600, 4096)
	if _, err := s.Execute(testContext, childCommand(s, worker, grant, Command{Operation: "post", Room: "lobby", Visibility: "public", Text: "worker post"}), "test-origin"); err != nil {
		t.Fatalf("%#v", err)
	}
	run(t, s, signedNow(s, main, Command{Operation: "device.revoke", Target: keyID(phone)}))
	fails(t, s, childCommand(s, worker, grant, Command{Operation: "post", Room: "lobby", Visibility: "public", Text: "after the device is gone"}), "delegation_inactive")
	st, err := json.Marshal(run(t, s, Command{Operation: "delegation.get", Target: keyID(worker)}).Data)
	if err != nil || !strings.Contains(string(st), `"issuer_revoked"`) {
		t.Fatalf("grant of a removed device %s", st)
	}
}

func TestDeviceMatchWordsAndCodes(t *testing.T) {
	w := DeviceMatchWords(strings.Repeat("0", 64))
	if strings.Join(w, " ") != "apple apple apple apple" {
		t.Fatal(w)
	}
	if DeviceCodeSHA256("k7qm-4xpd") != DeviceCodeSHA256("K7QM4XPD") || DeviceCodeSHA256("K7QM-4XPO") != DeviceCodeSHA256("K7QM4XP0") || DeviceCodeSHA256("K7QM-4XP") != "" || DeviceCodeSHA256("K7QM-4XPU") != "" {
		t.Fatal("code normalization")
	}
	for range 200 {
		code, err := newDeviceCode()
		if err != nil {
			t.Fatal(err)
		}
		if n, ok := normalizeDeviceCode(code); !ok || n != code {
			t.Fatalf("code %q does not read back", code)
		}
	}
}

func FuzzDeviceData(f *testing.F) {
	for _, seed := range []string{`{"schema":1,"label":"Chrome"}`, `{"schema":1,"code":"K7QM-4XPD"}`, `{"schema":1,"code_sha256":"` + strings.Repeat("a", 64) + `"}`, `{}`, `[]`, ``} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data string) {
		for _, op := range []string{"device.request", "device.request.get", "device.add"} {
			d, err := parseDeviceData(op, data)
			if err == nil && (len([]rune(d.Label)) > DeviceLabelMax || strings.ContainsAny(d.Label, "\r\n")) {
				t.Fatalf("%s accepted %q", op, data)
			}
		}
		normalizeDeviceCode(data)
	})
}
