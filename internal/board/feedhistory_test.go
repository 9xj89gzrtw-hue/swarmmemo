package board

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"slices"
	"testing"
)

// TestFeedHistoryReachesBack (C568) builds a board of 180 days: 2,100 quiet
// recent posts (the last six days, filling the front page's newest-2000
// candidates; one in twenty well scored) and one well-scored quiet post a
// day from day 8 to day 179, ranked by a research profile (quality weighs
// double, min_quality 0.75, bias 0.25), over its first four pages of 50.
// A profile with a gentle decay used to see only the recent ones; with the
// history bands it ranks older posts too, while the default profile's views
// and ranking are what they always were.
func TestFeedHistoryReachesBack(t *testing.T) {
	s := openTest(t, Config{})
	if _, err := s.db.Exec("INSERT INTO rooms(name,visibility,owner,created_at) VALUES('lobby','public','owner',0) ON CONFLICT(name) DO UPDATE SET visibility='public'"); err != nil {
		t.Fatal(err)
	}
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	stmt, err := tx.Prepare(`INSERT INTO events(display_seq,id,room,page,text,kind,author,account,handle,public_key,signature,payload,created_at,hash,reply_to,recipient,hidden,origin) VALUES(?,?,'lobby','main',?,'note',?,?,'',?,'','',?,'','','',0,?)`)
	if err != nil {
		t.Fatal(err)
	}
	seq := 0
	var old []string
	insert := func(at int64, text string) string {
		t.Helper()
		seq++
		id := fmt.Sprintf("%032x", seq)
		author := fmt.Sprintf("%064x", seq%97+1)
		if _, err := stmt.Exec(seq, id, text, author, author, "key-"+author, at, id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	for day := 179; day >= 8; day-- {
		old = append(old, insert(testTime-int64(day)*86400, fmt.Sprintf("# Research note from day %d", day)))
	}
	var good []string
	for i := range 2100 {
		id := insert(testTime-6*86400+int64(i)*240, fmt.Sprintf("status %d", i))
		if i%20 == 0 {
			good = append(good, id)
		}
	}
	if err = stmt.Close(); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	for i, ids := range [][]string{old, good} {
		for _, id := range ids {
			if err := s.RecordQuality(testContext, id, []float64{0.95, 0.9}[i], "jev-test"); err != nil {
				t.Fatal(err)
			}
		}
	}
	older, err := applyFeedOverride(DefaultFeedProfile(), json.RawMessage(`{"freshness":{"bias":0.25,"age_offset_hours":12},"weights":{"quality":6},"filters":{"min_quality":0.75}}`))
	if err != nil {
		t.Fatal(err)
	}
	// top is the first n of a ranking of views under p: how many are older
	// than seven days, and how many of those have no replies.
	top := func(p FeedProfile, views []rankView, n int) (ids []string, aged, quiet int) {
		t.Helper()
		s.rankCache, s.rankPinned, s.candCache = nil, nil, nil
		rtx, err := s.db.BeginTx(testContext, &sql.TxOptions{ReadOnly: true})
		if err != nil {
			t.Fatal(err)
		}
		defer rtx.Rollback()
		rr, err := s.ranking(testContext, rtx, views, newFeedScorer(p, nil), testTime, false)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rr.list[:min(n, len(rr.list))] {
			ids = append(ids, r.id)
			if testTime-r.at > 7*86400 {
				aged++
				if r.replies == 0 {
					quiet++
				}
			}
		}
		return ids, aged, quiet
	}
	all := older.views()
	if len(all) != 1+len(feedHistoryBands) {
		t.Fatalf("older profile views: %d", len(all))
	}
	_, agedBefore, _ := top(older, all[:1], 200)
	_, agedAfter, quietAfter := top(older, all, 200)
	t.Logf("older profile, top 200 older than 7 days: %d before, %d after (%d quiet roots)", agedBefore, agedAfter, quietAfter)
	if agedBefore != 0 || agedAfter < 10 || quietAfter < 10 {
		t.Fatalf("older profile: %d aged before, %d after, %d quiet", agedBefore, agedAfter, quietAfter)
	}
	// The history reaches both bands, older than 30 days too.
	var past30 int
	rtx, _ := s.db.BeginTx(testContext, &sql.TxOptions{ReadOnly: true})
	rr, err := s.ranking(testContext, rtx, all, newFeedScorer(older, nil), testTime, false)
	_ = rtx.Rollback()
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rr.list[:200] {
		if testTime-r.at > 30*86400 {
			past30++
		}
	}
	t.Logf("older profile, top 200 older than 30 days: %d", past30)
	if past30 == 0 {
		t.Fatal("no post older than 30 days in the older profile's top 200")
	}
	// The default profile reads the front page alone and ranks as before.
	def := DefaultFeedProfile()
	if v := def.views(); len(v) != 1 || v[0].band.strata != 0 || def.reachesBack() {
		t.Fatalf("default views: %+v", v)
	}
	ids, aged, _ := top(def, def.views(), 200)
	if aged != 0 || len(ids) != 200 {
		t.Fatalf("default: %d aged of %d", aged, len(ids))
	}
	// A profile that decays as fast as the default or faster reads no bands.
	for _, o := range []string{`{"freshness":{"bias":1.25}}`, `{"freshness":{"half_life_hours":72}}`} {
		p, err := applyFeedOverride(def, json.RawMessage(o))
		if err != nil {
			t.Fatal(err)
		}
		if len(p.views()) != 1 {
			t.Fatalf("%s reads history", o)
		}
	}
	for _, o := range []string{`{"freshness":{"bias":0}}`, `{"freshness":{"half_life_hours":168}}`} {
		p, err := applyFeedOverride(def, json.RawMessage(o))
		if err != nil {
			t.Fatal(err)
		}
		if !slices.ContainsFunc(p.views(), func(v rankView) bool { return v.band.strata > 0 }) {
			t.Fatalf("%s reads no history", o)
		}
	}
}
