package board

import (
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
)

// message.withdraw hides every version of the author's own message with the
// public reason, keeps the text, logs the signed command, and nobody else
// can withdraw or restore it.
func TestMessageWithdraw(t *testing.T) {
	s := openTest(t, Config{})
	author, owner, other := keyFor(231), keyFor(232), keyFor(233)
	for _, k := range []ed25519.PrivateKey{author, owner, other} {
		register(t, s, k)
	}
	run(t, s, signed(owner, Command{Operation: "room.create", Room: "forum"}))
	first := run(t, s, signed(author, Command{Operation: "post", Room: "forum", Text: "draft"})).Receipt.ID
	second := run(t, s, signed(author, Command{Operation: "post", Room: "forum", Text: "draft, edited", Data: `{"schema":1,"supersedes":"` + first + `"}`})).Receipt.ID

	fails(t, s, Command{Operation: "message.withdraw", MessageID: second}, "signature_required")
	fails(t, s, signed(other, Command{Operation: "message.withdraw", MessageID: second}), "not_author")
	fails(t, s, signed(owner, Command{Operation: "message.withdraw", MessageID: second}), "not_author")
	fails(t, s, signed(author, Command{Operation: "message.withdraw", MessageID: "missing"}), "not_found")

	got := run(t, s, signed(author, Command{Operation: "message.withdraw", MessageID: second}))
	if got.Data["reason"] != WithdrawnReason || len(got.Data["withdrawn"].([]string)) != 2 {
		t.Fatalf("withdraw: %+v", got.Data)
	}
	for _, id := range []string{first, second} {
		e := run(t, s, Command{Operation: "message.get", MessageID: id}).Messages[0]
		if !e.Hidden || e.HiddenBy != "author" || e.Reason != WithdrawnReason || e.Text != "" || e.Type != "tombstone" {
			t.Fatalf("withdrawn version %s: %+v", id, e)
		}
	}
	// Never deleted: the text stays in the database.
	if sqlCount(t, s, "SELECT count(*) FROM events WHERE id IN (?,?) AND text<>''", first, second) != 2 {
		t.Fatal("withdraw deleted the text")
	}
	fails(t, s, signed(author, Command{Operation: "message.withdraw", MessageID: first}), "already_hidden")
	fails(t, s, signed(owner, Command{Operation: "room.restore", MessageID: first, Reason: "bring it back"}), "not_author")
	fails(t, s, signed(author, Command{Operation: "post", Room: "forum", Text: "again", Data: `{"schema":1,"supersedes":"` + second + `"}`}), "supersede_hidden")
	log, _ := json.Marshal(run(t, s, Command{Operation: "room.modlog", Room: "forum"}).Data["entries"])
	if !strings.Contains(string(log), `"action":"withdraw"`) || !strings.Contains(string(log), WithdrawnReason) {
		t.Fatalf("modlog: %s", log)
	}

	// A room hide is the room's; the author cannot withdraw over it.
	hidden := run(t, s, signed(author, Command{Operation: "post", Room: "forum", Text: "spam"})).Receipt.ID
	run(t, s, signed(owner, Command{Operation: "room.hide", MessageID: hidden, Reason: "Spam."}))
	fails(t, s, signed(author, Command{Operation: "message.withdraw", MessageID: hidden}), "already_hidden")
}

// An app owns its room; a device's worker key posts, votes and withdraws
// what it posted, never its principal's posts; the app's own key hides.
func TestAppRoomWorkerKeys(t *testing.T) {
	s := openTest(t, Config{})
	app, person := keyFor(234), keyFor(235)
	register(t, s, app)
	register(t, s, person)
	run(t, s, signed(app, Command{Operation: "room.create", Room: "tieba"}))
	device := keyFor(236)
	run(t, s, grantCommand(s, app, device, "tieba", 3600, 1<<20, []string{"post", "vote", "message.withdraw", "messages.list"}))
	g := &DelegationContext{Schema: 1, GrantID: keyID(device), Generation: s.generation}
	byApp := run(t, s, signed(app, Command{Operation: "post", Room: "tieba", Text: "rules"})).Receipt.ID
	byDevice := run(t, s, childCommand(s, device, g, Command{Operation: "post", Room: "tieba", Visibility: "public", Text: "from a phone"})).Receipt.ID
	byPerson := run(t, s, signed(person, Command{Operation: "post", Room: "tieba", Text: "hello"})).Receipt.ID
	run(t, s, childCommand(s, device, g, Command{Operation: "vote", MessageID: byPerson, Data: `{"value":1}`}))
	fails(t, s, childCommand(s, device, g, Command{Operation: "message.withdraw", MessageID: byApp}), "not_author")
	fails(t, s, childCommand(s, device, g, Command{Operation: "message.withdraw", MessageID: byPerson}), "not_author")
	run(t, s, childCommand(s, device, g, Command{Operation: "message.withdraw", MessageID: byDevice}))
	run(t, s, signed(app, Command{Operation: "room.hide", MessageID: byPerson, Reason: "Off-topic."}))
	if sqlCount(t, s, "SELECT count(*) FROM events WHERE hidden=1 AND id IN (?,?)", byDevice, byPerson) != 2 {
		t.Fatal("withdraw and hide did not both apply")
	}
}

// App records are posts that stay out of every read people see unless a read
// asks for them, and they notify no one.
func TestAppRecords(t *testing.T) {
	s := openTest(t, Config{})
	app, person := keyFor(237), keyFor(238)
	register(t, s, app)
	register(t, s, person)
	run(t, s, signed(person, Command{Operation: "agent.register", Handle: "reader"}))
	run(t, s, signed(app, Command{Operation: "room.create", Room: "appdata"}))
	post := run(t, s, signed(person, Command{Operation: "post", Room: "appdata", Text: "a real post"})).Receipt.ID
	record := run(t, s, signed(app, Command{Operation: "post", Room: "appdata", Kind: "app-state", Text: `{"pinned":"` + post + `"} @reader`})).Receipt.ID
	fails(t, s, signed(app, Command{Operation: "post", Room: "appdata", Kind: "app-like", Text: "{}", ReplyTo: post}), "invalid_reply")
	fails(t, s, signed(app, Command{Operation: "post", Room: "lobby", Kind: "app-like", Text: "{}"}), "reserved_kind")
	fails(t, s, Command{Operation: "post", Room: "new-shared-room", Kind: "app-like", Text: "{}"}, "reserved_kind")
	if sqlCount(t, s, "SELECT count(*) FROM post_mentions WHERE event_id=?", record) != 0 {
		t.Fatal("an app record mentioned someone")
	}

	ids := func(r Result) string {
		var out []string
		for _, m := range r.Messages {
			out = append(out, m.ID)
		}
		return strings.Join(out, ",")
	}
	list := func(kind, data string) string {
		return ids(run(t, s, Command{Operation: "messages.list", Room: "appdata", Kind: kind, Data: data}))
	}
	if got := list("", ""); got != post {
		t.Fatalf("default read: %s", got)
	}
	if got := list("", `{"sort":"new"}`); got != post {
		t.Fatalf("sort new: %s", got)
	}
	if got := list("app-state", ""); got != record {
		t.Fatalf("by kind: %s", got)
	}
	if got := list("", `{"records":"only"}`); got != record {
		t.Fatalf("records only: %s", got)
	}
	if got := list("", `{"records":"include"}`); got != record+","+post {
		t.Fatalf("records include: %s", got)
	}
	fails(t, s, Command{Operation: "messages.list", Room: "appdata", Data: `{"records":"only","sort":"hot"}`}, "invalid_list_options")
	fails(t, s, Command{Operation: "messages.list", Room: "appdata", Data: `{"records":"all"}`}, "invalid_list_options")
	if got := ids(run(t, s, Command{Operation: "messages.list", Room: "appdata", Data: `{"sort":"hot"}`})); strings.Contains(got, record) {
		t.Fatalf("hot: %s", got)
	}
	if got := ids(run(t, s, Command{Operation: "agent.posts", Target: keyID(app)})); got != "" {
		t.Fatalf("agent posts: %s", got)
	}
	// The app owns the room, so its own updates carry the room's activity.
	updates := func(data string) string {
		return ids(run(t, s, signed(app, Command{Operation: "updates.get", Target: keyID(app), Data: data})))
	}
	if got := updates(""); strings.Contains(got, record) || !strings.Contains(got, post) {
		t.Fatalf("updates: %s", got)
	}
	// A device's record (here unsigned) reaches the app's own read only
	// with records include; the app's own posts are never its news.
	fromDevice := run(t, s, Command{Operation: "post", Room: "appdata", Kind: "app-like", Text: `{"post":"` + post + `"}`}).Receipt.ID
	if got := updates(""); strings.Contains(got, fromDevice) {
		t.Fatalf("updates: %s", got)
	}
	if got := updates(`{"schema":1,"records":"include"}`); !strings.Contains(got, post) || !strings.Contains(got, fromDevice) || strings.Contains(got, record) {
		t.Fatalf("updates with records: %s (post %s, device %s, record %s)", got, post, fromDevice, record)
	}
	fails(t, s, signed(app, Command{Operation: "updates.get", Target: keyID(app), Data: `{"schema":1,"records":"only"}`}), "invalid_request")
}
