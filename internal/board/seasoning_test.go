package board

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"
)

// storeBurst writes the burst detector's result (meta funnel.burst) with
// the given keys as the members of one cluster, or raw as it is.
func storeBurst(t *testing.T, s *Store, raw string, keys ...ed25519.PrivateKey) {
	t.Helper()
	if raw == "" {
		c := BurstCluster{ID: 1, From: testTime, To: testTime}
		for _, k := range keys {
			c.Members = append(c.Members, BurstMember{Account: keyID(k), CreatedAt: testTime, Family: "scripts", Reasons: []string{"creation_linked", "reply_linked"}})
		}
		b, err := json.Marshal(BurstResult{ComputedAt: testTime, Fast: len(keys), Clusters: []BurstCluster{c}})
		if err != nil {
			t.Fatal(err)
		}
		raw = string(b)
	}
	if _, err := s.db.Exec("INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", metaFunnelBurst, raw); err != nil {
		t.Fatal(err)
	}
}

// C546: a key created in a burst is not a seasoned voter. Its vote is taken
// and counted, and weighs only its standing in rankings, never a whole vote;
// a key outside every cluster still does after a day. An unreadable stored
// result flags nobody.
func TestBurstKeysAreNotSeasonedVoters(t *testing.T) {
	s := openTest(t, Config{})
	alice, ring, carol, fresh := keyFor(31), keyFor(32), keyFor(33), keyFor(34)
	post := postAs(t, s, alice, Command{Room: "lobby", Text: "a post to vote on", RequestID: "sv-a1"})
	seasoned(t, s, ring, carol)
	storeBurst(t, s, "", ring, keyFor(35))

	ctx := testContext
	for _, c := range []struct {
		key  ed25519.PrivateKey
		want bool
	}{{ring, false}, {carol, true}, {fresh, false}, {alice, false}} {
		got, err := seasonedVoter(ctx, s.db, keyID(c.key), s.now().Unix())
		if err != nil || got != c.want {
			t.Fatalf("seasonedVoter(%s) = %v %v, want %v", keyID(c.key)[:8], got, err, c.want)
		}
	}
	// alice's only post is minutes old: not seasoned either.

	r, err := voteAs(s, ring, post, "1", "sv-ring1")
	if err != nil || r.Data["votes"].(VoteCounts) != (VoteCounts{Up: 1, Score: 1}) {
		t.Fatalf("a burst key's vote is still taken and counted: %+v %v", r.Data, err)
	}
	if w := seasonedScore(t, s, post); w != 0 {
		t.Fatalf("a burst key's vote weighs %d whole votes", w)
	}
	var stored int
	if err := s.db.QueryRow("SELECT seasoned FROM votes WHERE event_id=? AND account=?", post, keyID(ring)).Scan(&stored); err != nil || stored != 0 {
		t.Fatalf("votes.seasoned = %d %v, want 0", stored, err)
	}
	if r, err = voteAs(s, carol, post, "1", "sv-carol1"); err != nil || r.Data["votes"].(VoteCounts) != (VoteCounts{Up: 2, Score: 2}) || seasonedScore(t, s, post) != 1 {
		t.Fatalf("a seasoned key outside the cluster weighs one whole vote: %+v %v score %d", r.Data, err, seasonedScore(t, s, post))
	}

	// A stored result that cannot be read flags nobody: the ring key's next
	// vote is seasoned again (and so is one a later run no longer lists).
	storeBurst(t, s, "{not json")
	if ok, err := seasonedVoter(ctx, s.db, keyID(ring), s.now().Unix()); err != nil || !ok {
		t.Fatalf("unreadable burst result: seasoned %v %v", ok, err)
	}
	if _, err = voteAs(s, ring, post, "1", "sv-ring2"); err != nil || seasonedScore(t, s, post) != 2 {
		t.Fatalf("re-vote after the result changed: %v score %d", err, seasonedScore(t, s, post))
	}
	storeBurst(t, s, `{"clusters":[{"members":[{"account":7}]}, "x"]}`)
	if ok, err := seasonedVoter(ctx, s.db, keyID(carol), s.now().Unix()); err != nil || !ok {
		t.Fatalf("odd burst result shapes: seasoned %v %v", ok, err)
	}
}

// C546: /stats and /api/stats/activity count new keys per day, each account
// once by its first key, and how many of them are burst members.
func TestActivityCountsNewKeysPerDay(t *testing.T) {
	s := openTest(t, Config{})
	a, b, c := keyFor(41), keyFor(42), keyFor(43)
	yesterday := testTime - 86400
	s.now = func() time.Time { return time.Unix(yesterday, 0) }
	postAs(t, s, a, Command{Room: "lobby", Text: "made yesterday", RequestID: "nk-a"})
	s.now = func() time.Time { return time.Unix(testTime, 0) }
	postAs(t, s, a, Command{Room: "lobby", Text: "back today", RequestID: "nk-a2"})
	postAs(t, s, b, Command{Room: "lobby", Text: "made today", RequestID: "nk-b"})
	postAs(t, s, c, Command{Room: "lobby", Text: "made today in a ring", RequestID: "nk-c"})
	storeBurst(t, s, "", c)
	act, err := s.computeActivity(testContext, time.Unix(testTime, 0))
	if err != nil {
		t.Fatal(err)
	}
	today, before := act.Days[len(act.Days)-1], act.Days[len(act.Days)-2]
	if today.NewKeys != 2 || today.NewKeysInBurst != 1 || before.NewKeys != 1 || before.NewKeysInBurst != 0 {
		t.Fatalf("new keys: today %d (%d in burst), yesterday %d (%d)", today.NewKeys, today.NewKeysInBurst, before.NewKeys, before.NewKeysInBurst)
	}
}
