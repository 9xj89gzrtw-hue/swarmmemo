package board

import (
	"context"
	"time"
)

// Seasoned voters (C546). A vote or a review weighs one whole vote in
// rankings, whatever the author's standing, only from a seasoned account: one
// with a visible public post at least VoterMinAge old that was not created in
// a burst. Keys are free and every client now makes one on its first write,
// so "post once, wait a day" alone is a cheap way to a whole vote; a key the
// burst detector (funnel_burst.go, C478) put in a cluster is one script's
// ring, and its votes weigh only its standing (0 below the vote floor), like
// a fresh key's. The vote count still counts every signed vote.
//
// The detector's last result is meta funnel.burst, written by the funnel
// recompute. A missing or unreadable result flags nobody; a key a later run
// no longer flags is seasoned again from its next vote. A vote keeps the
// seasoned flag it was cast with (votes.seasoned).

// burstMemberSQL is the SQL test that the account in col (an SQL expression)
// is a member of a stored burst cluster. It binds no parameters of its own,
// and a result of any other shape names nobody rather than failing the vote.
func burstMemberSQL(col string) string {
	return "EXISTS(SELECT 1 FROM meta bx, json_each(CASE WHEN json_valid(bx.value) THEN bx.value ELSE '{}' END,'$.clusters') bc," +
		" json_each(CASE WHEN bc.type='object' THEN bc.value ELSE '{}' END,'$.members') bm" +
		" WHERE bx.key='" + metaFunnelBurst + "' AND CASE WHEN bm.type='object' THEN json_extract(bm.value,'$.account') END=" + col + ")"
}

// seasonedVoterSQL answers 1 for a seasoned account: ?1 the account, ?2 the
// bound (now minus VoterMinAge).
var seasonedVoterSQL = "SELECT EXISTS(SELECT 1 FROM events e JOIN rooms r ON r.name=e.room WHERE e.account=?1 AND e.hidden=0 AND r.visibility='public' AND e.created_at<=?2) AND NOT " + burstMemberSQL("?1")

// seasonedVoter reports whether account is a seasoned voter at now. q is the
// caller's transaction when it holds one (never the pool under a held
// transaction).
func seasonedVoter(ctx context.Context, q rowQuerier, account string, now int64) (bool, error) {
	var seasoned bool
	err := q.QueryRowContext(ctx, seasonedVoterSQL, account, now-int64(VoterMinAge/time.Second)).Scan(&seasoned)
	return seasoned, err
}
