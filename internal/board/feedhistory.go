package board

// Feed history (C568): a profile whose decay is gentle asks for older
// posts, but the front page's candidates are its newest posts (of the last
// 30 days), so recency decided before the weights could. Such a profile
// also draws a bounded, age-stratified sample of older top-level posts,
// quiet ones included: two bands, 7 to 30 days in one-day strata and 30 to
// 180 days in five-day strata, the newest few rankable posts of each
// stratum, at most a third of HotCandidates in all. The profile then ranks
// the union as usual. The default profile, and any profile that decays
// faster, reads exactly the candidates it always did.

import (
	"context"
	"database/sql"
	"strings"
)

const (
	FeedHistoryBias     = 1.0   // a power-law bias at or below this reaches back
	FeedHistoryHalfLife = 168.0 // as does a half-life of at least this many hours
	FeedHistoryMaxDays  = 180   // the oldest band's far edge
	feedHistoryDay      = 86400
)

// feedBand is an age band of a history view: posts from minAge to maxAge
// seconds old, in strata of equal time, each giving at most its share of
// the view's limit.
type feedBand struct {
	minAge, maxAge int64
	strata         int
}

// feedHistoryBands are the bands and each one's candidates: 23 strata of 12
// and 30 of 8, 516 posts at most (HotCandidates/3 is 666).
var feedHistoryBands = []struct {
	band  feedBand
	limit int
}{
	{feedBand{7 * feedHistoryDay, 30 * feedHistoryDay, 23}, 23 * 12},
	{feedBand{30 * feedHistoryDay, FeedHistoryMaxDays * feedHistoryDay, 30}, 30 * 8},
}

// reachesBack is whether p's decay is gentle enough to rank posts older
// than the front page's window: all-time top, a bias at or below
// FeedHistoryBias, or a half-life of at least FeedHistoryHalfLife.
func (p FeedProfile) reachesBack() bool {
	if p.Freshness.HalfLifeHours != nil {
		return *p.Freshness.HalfLifeHours >= FeedHistoryHalfLife
	}
	return *p.Freshness.Bias <= FeedHistoryBias
}

// historyViews are front's history bands, for a profile that reaches back.
func historyViews(front rankView) []rankView {
	views := make([]rankView, 0, len(feedHistoryBands))
	for _, b := range feedHistoryBands {
		views = append(views, rankView{src: front.src, where: front.where, args: front.args, limit: b.limit, copies: true, band: b.band})
	}
	return views
}

// bandCandidates collects v's band: for each stratum, the newest rankable
// posts meeting cond, at most v.limit/strata, in one query of bounded index
// walks (each stratum's sequences found by bisection, seqAtOrBefore). It
// reads only tx.
func (s *Store) bandCandidates(ctx context.Context, tx *sql.Tx, v rankView, rd *rankRead, cond string, args []any, collect func(string, []any) error) error {
	b := v.band
	per := v.limit / b.strata
	if per <= 0 {
		return nil
	}
	step := (b.maxAge - b.minAge) / int64(b.strata)
	newer := rd.now - b.minAge
	hi, err := seqAtOrBefore(ctx, tx, newer, rd.top)
	if err != nil {
		return err
	}
	parts := make([]string, 0, b.strata)
	var qargs []any
	for i := 1; i <= b.strata && hi > 0; i++ {
		older := rd.now - b.minAge - int64(i)*step
		lo, err := seqAtOrBefore(ctx, tx, older, hi)
		if err != nil {
			return err
		}
		if lo < hi {
			source, sargs, err := v.src.rangeSQL(ctx, tx, lo, hi, 2*per)
			if err != nil {
				return err
			}
			parts = append(parts, "SELECT seq FROM (SELECT e.seq FROM ("+source+") s CROSS JOIN events e ON e.seq=s.seq JOIN rooms r ON r.name=e.room WHERE "+cond+" AND e.created_at<=? AND e.created_at>? ORDER BY e.seq DESC LIMIT ?)")
			qargs = append(append(append(qargs, sargs...), args...), newer, older, per)
		}
		hi, newer = lo, older
	}
	if len(parts) == 0 {
		return nil
	}
	return collect(strings.Join(parts, " UNION ALL "), qargs)
}
