package board

import (
	"crypto/ed25519"
	"regexp"
	"slices"
	"testing"
	"time"
)

// C575: Your threads lists every public thread the agent started or posted
// in, or was replied to, addressed or mentioned in, over the last 30 days,
// newest activity first, paged with a cursor.
func TestUpdatesThreadsListsAnAgentsThreads(t *testing.T) {
	s := openTest(t, updatesConfig())
	me, bob, carol := keyFor(81), keyFor(82), keyFor(83)
	day := int64(0)
	at := func(d int64) { day = d; s.now = func() time.Time { return time.Unix(testTime+d*86400, 0) } }
	post := func(k ed25519.PrivateKey, c Command) string {
		c.Operation, c.Timestamp = "post", testTime+day*86400
		if c.Room == "" {
			c.Room = "lobby"
		}
		return run(t, s, signed(k, c)).Receipt.ID
	}
	run(t, s, signed(me, Command{Operation: "agent.register", Handle: "threader"}))
	run(t, s, signed(bob, Command{Operation: "agent.register", Handle: "bob"}))
	run(t, s, signed(carol, Command{Operation: "agent.register", Handle: "carol"}))

	// Day 0: outside the window by the time of the read (day 40).
	at(0)
	old := post(me, Command{Text: "An old question."})
	oldAnswer := post(bob, Command{Text: "An old answer.", ReplyTo: old})
	// Day 15: a thread of mine nobody touched since; still in the window.
	at(15)
	started := post(me, Command{Room: "workshop", Text: "# Started here\nMore detail."})
	// Day 20: bob's thread I posted in, deep down; carol answers later.
	at(20)
	bobs := post(bob, Command{Text: "Bob asks something."})
	mid := post(carol, Command{Text: "Carol chimes in.", ReplyTo: bobs})
	mine := post(me, Command{Text: "I answer carol.", ReplyTo: mid})
	// Day 25: a thread where I am only mentioned; one where I am addressed.
	at(25)
	mentioned := post(carol, Command{Text: "Ask @threader about this."})
	addressed := post(bob, Command{Room: "workshop", Text: "A public DM.", To: keyID(me)})
	// Day 30: a thread I never touched stays out.
	at(30)
	post(carol, Command{Text: "Unrelated."})
	// Day 35: carol replies under my answer in bob's thread: its activity moves.
	at(35)
	latest := post(carol, Command{Text: "Carol again.", ReplyTo: mine})
	// Day 36: my old thread from day 0 gets a reply: replied to me, in the window.
	at(36)
	revived := post(bob, Command{Text: "Coming back to this.", ReplyTo: old})
	at(40)

	read := func(cursor string, limit int) Result {
		return run(t, s, Command{Operation: "updates.get", Target: keyID(me), Cursor: cursor, Limit: limit, Data: `{"schema":1,"threads":true}`})
	}
	res := read("", 0)
	threads, _ := res.Data["threads"].([]ThreadSummary)
	got := []string{}
	for _, th := range threads {
		got = append(got, th.ID)
	}
	want := []string{old, bobs, addressed, mentioned, started}
	if !slices.Equal(got, want) {
		t.Fatalf("threads %v, want %v (newest activity first)", got, want)
	}
	if res.Data["has_more"] != false || res.NextCursor != "" || len(res.Messages) != 0 {
		t.Fatalf("one page, no messages: %+v %q", res.Data, res.NextCursor)
	}
	byID := map[string]ThreadSummary{}
	for _, th := range threads {
		byID[th.ID] = th
	}
	if th := byID[bobs]; th.LastID != latest || th.Messages != 4 || th.Title != "Bob asks something." || th.AuthorHandle != "bob" ||
		!slices.Equal(th.Reasons, []string{"posted", "replied"}) || len(th.Participants) != 2 || th.Participants[0].Handle != "carol" || th.Participants[1].Handle != "bob" {
		t.Fatalf("bob's thread: %+v", th)
	}
	if th := byID[bobs]; !slices.Equal(th.Updates, []string{latest}) {
		t.Fatalf("bob's thread's updates are the reply to me: %v", th.Updates)
	}
	if th := byID[old]; !slices.Equal(th.Updates, []string{revived, oldAnswer}) || len(byID[started].Updates) != 0 || !slices.Equal(byID[mentioned].Updates, []string{mentioned}) || !slices.Equal(byID[addressed].Updates, []string{addressed}) {
		t.Fatalf("updates by thread: %+v", byID)
	}
	if th := byID[old]; th.LastID != revived || !slices.Equal(th.Reasons, []string{"started", "replied"}) {
		t.Fatalf("a reply in the window brings an old thread back: %+v", th)
	}
	if th := byID[started]; th.Title != "Started here" || th.Room != "workshop" || !slices.Equal(th.Reasons, []string{"started", "posted"}) || len(th.Participants) != 0 {
		t.Fatalf("my own thread: %+v", th)
	}
	if th := byID[mentioned]; !slices.Equal(th.Reasons, []string{"mentioned"}) {
		t.Fatalf("a mention: %+v", th)
	}
	if th := byID[addressed]; !slices.Equal(th.Reasons, []string{"addressed"}) {
		t.Fatalf("a public DM: %+v", th)
	}

	// Pages of two, joined, are the one page.
	paged := []string{}
	cursor := ""
	for i := 0; i < 5; i++ {
		page := read(cursor, 2)
		for _, th := range page.Data["threads"].([]ThreadSummary) {
			paged = append(paged, th.ID)
		}
		if page.Data["has_more"] != (page.NextCursor != "") {
			t.Fatalf("has_more and next_cursor disagree: %+v %q", page.Data, page.NextCursor)
		}
		if cursor = page.NextCursor; cursor == "" {
			break
		}
	}
	if !slices.Equal(paged, want) {
		t.Fatalf("paged %v, want %v", paged, want)
	}

	mineCursor := read("", 2).NextCursor

	// 30 days on, with nothing new, nothing is listed.
	at(80)
	if res := read("", 0); len(res.Data["threads"].([]ThreadSummary)) != 0 {
		t.Fatalf("the window is 30 days: %+v", res.Data["threads"])
	}

	// Another agent's cursor is refused; options do not mix.
	if _, err := s.Execute(testContext, Command{Operation: "updates.get", Target: keyID(bob), Cursor: mineCursor, Data: `{"schema":1,"threads":true}`}, "test-origin"); err == nil || mineCursor == "" {
		t.Fatal("a bad cursor was accepted")
	}
	if _, err := s.Execute(testContext, Command{Operation: "updates.get", Target: keyID(me), Data: `{"schema":1,"threads":true,"counts":true}`}, "test-origin"); err == nil {
		t.Fatal("threads with counts was accepted")
	}
	if _, err := s.Execute(testContext, Command{Operation: "updates.get", Data: `{"schema":1,"threads":true}`}, "test-origin"); err == nil {
		t.Fatal("threads without an agent was accepted")
	}
}

// Every table the threads read touches is reached by an index: no scan of
// events (or of an alias of it) at any step.
func TestUpdatesThreadsQueriesUseIndexes(t *testing.T) {
	s := openTest(t, updatesConfig())
	scan := regexp.MustCompile(`^SCAN (events|e|p|r|c|pm|i|identities|post_mentions)\b`)
	for _, q := range []struct {
		sql  string
		args []any
	}{{threadsWalk, []any{"a", 0, 10, 10}}, {threadTitlesQuery(2), []any{"a", "b", "a", "b"}}} {
		rows, err := s.db.Query("EXPLAIN QUERY PLAN "+q.sql, q.args...)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var id, parent, unused int
			var detail string
			if err = rows.Scan(&id, &parent, &unused, &detail); err != nil {
				t.Fatal(err)
			}
			if scan.MatchString(detail) {
				t.Errorf("a full scan: %s", detail)
			}
		}
		rows.Close()
	}
}
