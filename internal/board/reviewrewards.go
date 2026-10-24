package board

// Review rewards (RFC 0015 §5.6 as amended by RFC 0019; C201): a standing,
// automatic incentive for the first evidence-backed community reviews of a
// subject. No work items and no posts: a review that qualifies gets a
// pending reward in its write receipt, a sweep pays it as granted credit
// from the day's grant pool once its hold is over, and the surfaces (the
// receipt, subject.get and /s/ID, find, /capabilities, /api/stats, the
// ledger journal, allowance.get and journal.get) say so.
//
// The reward is a row of review_evidence, like a lab record's: evidence id
// RewardEvidence on the review that earned it, class reward, state unknown
// while pending, verified once paid and failed once cancelled, its terms in
// detail. It is not cited evidence and never sets a review's class. The
// payment itself is a ledger grant whose public reference is the review.
// So the schema is unchanged.
//
// Who earns: a current, visible community review (not lab, not
// outside_source) whose class, from verified evidence only, is one the
// parameters price (paid_use and work in full, observed at 0.4; opinion and
// free_use nothing), whose relationship is not owner, affiliate or paid,
// by a reviewer whose root is not an owner's root and whose v(s) is above
// zero. Once per root per subject, ever; only the first first_roots roots
// of a subject in window_days; caps per account and per subject per UTC
// day, and a daily total paid. The verdict never matters; votes never pay.
//
// Amount: base × evidence factor × v(s), whole credits. v(s) is the vote
// weight of the reviewer's standing, a whole vote for a reviewer seasoned
// when it reviewed (trust.Params.FlooredVoteWeight, RFC 0021 §12 and §14).

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sort"
	"strconv"
	"strings"

	"swarmmemo/internal/allowance"
	"swarmmemo/internal/ledger"
	"swarmmemo/internal/services"
)

// ReviewRewardsParamsNamespace holds the reward parameters, versioned like
// every other operator parameter (swarmmemo params set reviews_rewards).
const ReviewRewardsParamsNamespace = "reviews_rewards"

// RewardEvidence is the evidence id of a review's reward row.
const RewardEvidence = "reward:"

// ReviewRewardOp is the ledger operation of a paid review reward; its public
// reference is the review's id.
const ReviewRewardOp = "review.reward"

// rewardClasses are the classes a reward may price, best first.
var rewardClasses = []string{"paid_use", "work", "observed", "free_use"}

// reviewRewardsParams are the reward parameters (the namespace's body).
type reviewRewardsParams struct {
	Schema  int  `json:"schema"`
	Enabled bool `json:"enabled"`
	// BaseCredits is a full reward: base × evidence factor × v(s).
	BaseCredits int64 `json:"base_credits"`
	// EvidenceFactorsPPM prices each evidence class, in ppm; a class it
	// leaves out (opinion always) earns nothing.
	EvidenceFactorsPPM map[string]int64 `json:"evidence_factors_ppm"`
	// FirstRoots is how many independent roots earn per subject in
	// WindowDays.
	FirstRoots int64 `json:"first_roots"`
	WindowDays int64 `json:"window_days"`
	// HoldHours is the hold between the review and the payment.
	HoldHours int64 `json:"hold_hours"`
	// The caps: rewards per account and per subject per UTC day (by the
	// review's day), and credits paid per UTC day in all.
	PerAccountPerDay int64 `json:"per_account_per_day"`
	PerSubjectPerDay int64 `json:"per_subject_per_day"`
	DailyCredits     int64 `json:"daily_credits"`
}

// defaultReviewRewardsParams is the namespace's version 0.
func defaultReviewRewardsParams() reviewRewardsParams {
	return reviewRewardsParams{Schema: 1, Enabled: true, BaseCredits: 100,
		EvidenceFactorsPPM: map[string]int64{"paid_use": 1_000_000, "work": 1_000_000, "observed": 400_000},
		FirstRoots:         5, WindowDays: 90, HoldHours: 72, PerAccountPerDay: 5, PerSubjectPerDay: 3, DailyCredits: 1000}
}

var reviewRewardsKeys = []string{"schema", "enabled", "base_credits", "evidence_factors_ppm", "first_roots", "window_days", "hold_hours", "per_account_per_day", "per_subject_per_day", "daily_credits"}

func parseReviewRewardsParams(body []byte) (reviewRewardsParams, error) {
	var p reviewRewardsParams
	shape := fmt.Sprintf("reviews_rewards params: a strict JSON object of %v", reviewRewardsKeys)
	var keys map[string]json.RawMessage
	if json.Unmarshal(body, &keys) != nil || len(keys) != len(reviewRewardsKeys) {
		return p, errors.New(shape)
	}
	for _, k := range reviewRewardsKeys {
		if _, ok := keys[k]; !ok {
			return p, errors.New(shape)
		}
	}
	if err := services.StrictObject(body, &p); err != nil {
		return p, errors.New(shape)
	}
	in := func(name string, v, lo, hi int64) error {
		if v < lo || v > hi {
			return fmt.Errorf("reviews_rewards params: %s is %d to %d", name, lo, hi)
		}
		return nil
	}
	for _, c := range []struct {
		name      string
		v, lo, hi int64
	}{{"schema", int64(p.Schema), 1, 1}, {"base_credits", p.BaseCredits, 1, 100_000}, {"first_roots", p.FirstRoots, 1, 1000}, {"window_days", p.WindowDays, 1, 3650},
		{"hold_hours", p.HoldHours, 1, 24 * 30}, {"per_account_per_day", p.PerAccountPerDay, 1, 1000}, {"per_subject_per_day", p.PerSubjectPerDay, 1, 1000}, {"daily_credits", p.DailyCredits, 0, 1_000_000_000}} {
		if err := in(c.name, c.v, c.lo, c.hi); err != nil {
			return p, err
		}
	}
	for class, f := range p.EvidenceFactorsPPM {
		if !slices.Contains(rewardClasses, class) {
			return p, fmt.Errorf("reviews_rewards params: evidence_factors_ppm prices %v only (opinion earns nothing)", rewardClasses)
		}
		if err := in("evidence_factors_ppm."+class, f, 0, 1_000_000); err != nil {
			return p, err
		}
	}
	return p, nil
}

// barredRelationship reports whether a relationship weighs 0 in the
// community order (owner, affiliate, paid; lab and outside_source are not
// community reviews at all): such a review earns nothing.
func barredRelationship(rel string) bool {
	f, ok := ReviewRelationshipFactors[rel]
	return ok && f == 0
}

func init() {
	ledger.RegisterNamespace(ReviewRewardsParamsNamespace, ledger.Namespace{
		Version: 0,
		Body: func() []byte {
			b, _ := json.Marshal(defaultReviewRewardsParams())
			return b
		},
		Validate: func(b []byte) error { _, err := parseReviewRewardsParams(b); return err },
	})
}

// rewardTerms are the parameters in effect and whether rewards run: REVIEWS
// and the ledger on, enabled, and a credit grant pool to pay from. off says
// why not.
type rewardTerms struct {
	reviewRewardsParams
	version int64
	off     string
}

func (t rewardTerms) on() bool { return t.off == "" }

// reviewRewardTerms reads the terms through q (the caller's transaction, or
// the pool outside one).
func (s *Store) reviewRewardTerms(ctx context.Context, q allowance.Querier, now int64) (rewardTerms, error) {
	t := rewardTerms{reviewRewardsParams: defaultReviewRewardsParams()}
	switch {
	case !s.ReviewsEnabled():
		t.off = "reviews_off"
		return t, nil
	case s.config.Features.Ledger != LedgerOn:
		t.off = "ledger_off"
		return t, nil
	}
	version, body, err := s.ledger.params.Params(ctx, q, ReviewRewardsParamsNamespace, now)
	if err != nil {
		return t, err
	}
	if len(body) > 0 {
		if t.reviewRewardsParams, err = parseReviewRewardsParams(body); err != nil {
			return t, err
		}
	}
	t.version = version
	if !t.Enabled {
		t.off = "paused"
		return t, nil
	}
	ap, _, err := s.ledger.led.Params(ctx, q, now)
	if err != nil {
		return t, err
	}
	if rp := ap.Resources[allowance.Credit]; rp == nil || rp.Budget <= 0 || rp.GrantSharePPM <= 0 || t.DailyCredits <= 0 {
		t.off = "no_grant_pool"
	}
	return t, nil
}

// rewardOffNotes say why rewards do not run.
var rewardOffNotes = map[string]string{
	"reviews_off":   "Reviews are not enabled on this board.",
	"ledger_off":    "The allowance ledger is not on, so there is no grant pool to pay from.",
	"paused":        "Review rewards are paused by the operator (the reviews_rewards parameters).",
	"no_grant_pool": "This board has no credit grant pool to pay review rewards from today.",
}

// ReviewReward is a review's reward as its receipt, its card and the
// journal show it. State is pending, paid, cancelled, none or
// pending_evidence (a tx: payment not read on chain yet: nothing is decided
// until it is; Evidence is then "pending" and Pending names the ids); Amount
// is in credits; Review is the review that holds it when that is an earlier
// version of the reviewer's review of the subject.
type ReviewReward struct {
	State     string   `json:"state"`
	Evidence  string   `json:"evidence,omitempty"`
	Pending   []string `json:"pending_evidence,omitempty"`
	Amount    int64    `json:"amount,omitempty"`
	DueAt     int64    `json:"due_at,omitempty"`
	SettledAt int64    `json:"settled_at,omitempty"`
	Class     string   `json:"evidence_class,omitempty"`
	Reason    string   `json:"reason,omitempty"`
	Note      string   `json:"note,omitempty"`
	Review    string   `json:"review,omitempty"`
	Subject   string   `json:"subject,omitempty"`
}

// rewardDetail is a reward row's detail: the terms fixed when it was
// offered, and the outcome.
type rewardDetail struct {
	Amount        int64  `json:"amount"`
	DueAt         int64  `json:"due_at"`
	Root          string `json:"root"`
	Class         string `json:"class"`
	BaseCredits   int64  `json:"base_credits"`
	FactorPPM     int64  `json:"factor_ppm"`
	VPPM          int64  `json:"v_ppm"`
	ParamsVersion int64  `json:"params_version"`
	SettledAt     int64  `json:"settled_at,omitempty"`
	Reason        string `json:"reason,omitempty"`
}

// rewardStates map a reward row's state to the reward's.
var rewardStates = map[string]string{"unknown": "pending", "verified": "paid", "failed": "cancelled"}

func (d rewardDetail) reward(state, review string) *ReviewReward {
	r := &ReviewReward{State: rewardStates[state], Amount: d.Amount, DueAt: d.DueAt, SettledAt: d.SettledAt, Class: d.Class, Reason: d.Reason, Review: review}
	if r.State == "cancelled" {
		r.Note = rewardCancelNotes[d.Reason]
	}
	return r
}

// The reasons a review earns nothing, as the receipt says them.
var rewardNoneNotes = map[string]string{
	"not_a_community_review": "Lab assessments and outside sources earn no review reward.",
	"relationship":           "Owner, affiliate and paid reviews earn no review reward.",
	"owner_root":             "The reviewer shares a root (a verified domain) with the subject's owner.",
	"evidence_class":         "Rewards need verified evidence of paid use (call:), work (work:) or a fetch (fetch:); an opinion earns nothing.",
	"no_standing":            "v(standing) is 0: an account earns once it has a public post at least a day old, or standing (standing.ways lists the steps).",
	"already_rewarded":       "Your root already has a reward for this subject.",
	"no_slots_left":          "The first reviewers of this subject in the window already earned its rewards.",
	"account_daily_cap":      "You reached today's review rewards; the cap resets at 00:00 UTC.",
	"subject_daily_cap":      "This subject reached today's review rewards; try again after 00:00 UTC.",
}

// The public reasons a pending reward is cancelled.
var rewardCancelNotes = map[string]string{
	"review_hidden":           "The review was hidden during the hold.",
	"superseded_not_eligible": "The reviewer's newer review of the subject does not qualify.",
	"evidence_not_verified":   "The review's evidence is no longer verified.",
	"affiliated":              "The reviewer was found to own or share a root with the subject's owner.",
	"relationship":            "The reviewer's current review declares an owner, affiliate or paid relationship.",
	"already_rewarded":        "Another account of the reviewer's root holds this subject's reward.",
}

// RewardPendingEvidence is a reward's state while the evidence that could
// earn it is still being checked (a tx: payment waiting to be read on Base).
const RewardPendingEvidence = "pending_evidence"

// pendingEvidenceReward is the reward of a review whose only qualifying
// evidence is still being checked: undecided, not none.
func pendingEvidenceReward(ids []string) *ReviewReward {
	return &ReviewReward{State: RewardPendingEvidence, Evidence: "pending", Pending: ids,
		Note: "Pending evidence check: " + strings.Join(ids, ", ") + " is read on Base after the review (within a day). If it verifies, the reward is offered then; the review's card (message.get with this review's id) shows its reward and each evidence state."}
}

func noReward(reason string) *ReviewReward {
	return &ReviewReward{State: "none", Reason: reason, Note: rewardNoneNotes[reason]}
}

// rewardAmount is base × factor × v, in whole credits, rounded.
func rewardAmount(base, factorPPM, vPPM int64) int64 {
	return (base*factorPPM*vPPM + 500_000_000_000) / 1_000_000_000_000
}

// reviewRewardRow is one reward row with its review.
type reviewRewardRow struct {
	eventID, state, subject, account string
	createdAt                        int64
	detail                           rewardDetail
}

const reviewRewardColumns = `v.event_id,v.state,v.detail,r.subject,r.account,r.created_at`

func scanReviewRewards(rows *sql.Rows) ([]reviewRewardRow, error) {
	defer rows.Close()
	var out []reviewRewardRow
	for rows.Next() {
		var w reviewRewardRow
		var detail string
		if err := rows.Scan(&w.eventID, &w.state, &detail, &w.subject, &w.account, &w.createdAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(detail), &w.detail); err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

// subjectRewards reads a subject's reward rows (through reviews_subject).
func subjectRewards(ctx context.Context, q allowance.Querier, subject string) ([]reviewRewardRow, error) {
	rows, err := q.QueryContext(ctx, "SELECT "+reviewRewardColumns+" FROM reviews r JOIN review_evidence v ON v.event_id=r.event_id AND v.evidence=? WHERE r.subject=?", RewardEvidence, subject)
	if err != nil {
		return nil, err
	}
	return scanReviewRewards(rows)
}

// offerReviewReward decides a fresh review's reward in the posting
// transaction, once its rows are written, and records a pending one. It
// returns what the receipt says; nil while REVIEWS is off.
func (s *Store) offerReviewReward(ctx context.Context, tx *sql.Tx, p *pendingReview, eventID, class, raised string, now int64) (*ReviewReward, error) {
	if !s.ReviewsEnabled() {
		return nil, nil
	}
	t, err := s.reviewRewardTerms(ctx, tx, now)
	if err != nil {
		return nil, err
	}
	if !t.on() {
		return &ReviewReward{State: "none", Reason: "rewards_off", Note: rewardOffNotes[t.off]}, nil
	}
	sub := p.review.Subject.ID
	rel := p.review.Relationship
	if raised != "" {
		rel = raised
	}
	switch {
	case rel == "lab" || rel == "outside_source":
		return noReward("not_a_community_review"), nil
	case barredRelationship(rel):
		return noReward("relationship"), nil
	}
	// The reward an earlier version of this account's review holds carries
	// over: the sweep pays it against the review current when it is due.
	existing, err := subjectRewards(ctx, tx, sub)
	if err != nil {
		return nil, err
	}
	factor := t.EvidenceFactorsPPM[class]
	for _, w := range existing {
		if w.account == p.account && w.state != "failed" {
			out := w.detail.reward(w.state, w.eventID)
			out.Note = "Carried from your earlier review of this subject; paid once, against your current review when due."
			if w.state == "unknown" && factor <= 0 {
				out.Note = "Your earlier review's reward is pending, but this review's evidence does not qualify: it will be cancelled when due unless a qualifying review replaces this one."
			}
			return out, nil
		}
	}
	if factor <= 0 {
		return noReward("evidence_class"), nil
	}
	root, err := s.accountRoot(ctx, tx, p.account, now)
	if err != nil {
		return nil, err
	}
	for _, w := range existing {
		if w.detail.Root == root || w.account == p.account {
			return noReward("already_rewarded"), nil
		}
	}
	if shared, err := s.sharesOwnerRoot(ctx, tx, p.review.Subject.ID, p.account, root, now); err != nil || shared {
		if err != nil {
			return nil, err
		}
		return noReward("owner_root"), nil
	}
	v, err := s.voteWeightPPM(ctx, tx, p.account, p.seasoned, now)
	if err != nil {
		return nil, err
	}
	amount := rewardAmount(t.BaseCredits, factor, v)
	if amount <= 0 {
		return noReward("no_standing"), nil
	}
	roots := map[string]bool{}
	var subjectToday int64
	// The caps count the review's own UTC day and the hold starts at the
	// review (PROTOCOL: "by the review's day", "72 hours after the review"):
	// a tx: review verified after midnight is counted on the day it was
	// posted, not the day it verified (newbotlabor, round 7).
	posted := now
	if p.createdAt > 0 && p.createdAt < now {
		posted = p.createdAt
	}
	midnight := posted - posted%86400
	next := midnight + 86400
	for _, w := range existing {
		if w.state == "failed" {
			continue
		}
		if w.createdAt > now-t.WindowDays*86400 {
			roots[w.detail.Root] = true
		}
		if w.createdAt >= midnight && w.createdAt < next {
			subjectToday++
		}
	}
	if int64(len(roots)) >= t.FirstRoots {
		return noReward("no_slots_left"), nil
	}
	var accountToday int64
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM reviews r JOIN review_evidence v ON v.event_id=r.event_id AND v.evidence=? AND v.state<>'failed' WHERE r.account=? AND r.created_at>=? AND r.created_at<?`,
		RewardEvidence, p.account, midnight, next).Scan(&accountToday); err != nil {
		return nil, err
	}
	if accountToday >= t.PerAccountPerDay {
		return noReward("account_daily_cap"), nil
	}
	if subjectToday >= t.PerSubjectPerDay {
		return noReward("subject_daily_cap"), nil
	}
	d := rewardDetail{Amount: amount, DueAt: max(posted+t.HoldHours*3600, now), Root: root, Class: class, BaseCredits: t.BaseCredits, FactorPPM: factor, VPPM: v, ParamsVersion: t.version}
	raw, _ := json.Marshal(d)
	if _, err = tx.ExecContext(ctx, "INSERT INTO review_evidence(event_id,evidence,class,state,checked_at,detail) VALUES(?,?,'reward','unknown',?,?)", eventID, RewardEvidence, now, string(raw)); err != nil {
		return nil, err
	}
	return d.reward("unknown", ""), nil
}

// sharesOwnerRoot reports whether account owns the subject now, or its root
// is one of the subject's owners' roots.
func (s *Store) sharesOwnerRoot(ctx context.Context, tx *sql.Tx, subjectID, account, root string, now int64) (bool, error) {
	sub, ok, err := lookupSubject(ctx, tx, subjectID)
	if err != nil || !ok {
		return false, err
	}
	owners, err := s.subjectOwners(ctx, tx, sub)
	if err != nil {
		return false, err
	}
	for _, o := range owners {
		if o.Account == account {
			return true, nil
		}
		r, err := s.accountRoot(ctx, tx, o.Account, now)
		if err != nil {
			return false, err
		}
		if r == root {
			return true, nil
		}
	}
	return false, nil
}

// SweepReviewRewards settles due review rewards in its own short
// transaction (SweepAllowance runs it every minute after its own).
func (s *Store) SweepReviewRewards(ctx context.Context) (int, error) {
	if !s.ReviewsEnabled() || s.config.Features.Ledger != LedgerOn {
		return 0, nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	n, err := s.settleReviewRewards(ctx, tx, s.now().Unix(), ledger.SweepMax)
	if err != nil {
		return 0, err
	}
	return n, tx.Commit()
}

// settleReviewRewards pays or cancels up to max due rewards, oldest due
// first, in the caller's transaction: nothing here reads the pool. Each
// payment and its row change are one savepoint, so a reward is paid once
// whatever restarts. While rewards are paused or the grant
// pool is missing, pending rewards wait. The day's total and the pool's
// water bound what is paid: once either is reached nothing more is paid
// that UTC day, and the rest waits in order.
func (s *Store) settleReviewRewards(ctx context.Context, tx *sql.Tx, now int64, max int) (int, error) {
	if !s.ReviewsEnabled() {
		return 0, nil
	}
	t, err := s.reviewRewardTerms(ctx, tx, now)
	if err != nil || !t.on() {
		return 0, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT `+reviewRewardColumns+` FROM review_evidence v JOIN reviews r ON r.event_id=v.event_id
 WHERE v.evidence=? AND v.state='unknown' AND CAST(json_extract(v.detail,'$.due_at') AS INTEGER)<=? ORDER BY CAST(json_extract(v.detail,'$.due_at') AS INTEGER),v.event_id LIMIT ?`, RewardEvidence, now, max)
	if err != nil {
		return 0, err
	}
	due, err := scanReviewRewards(rows)
	if err != nil {
		return 0, err
	}
	if len(due) == 0 {
		return 0, nil
	}
	paidToday, err := rewardsPaidOn(ctx, tx, now/86400)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, w := range due {
		amount, reason, err := s.rewardOutcome(ctx, tx, t, w, now)
		if err != nil {
			return n, err
		}
		if reason != "" {
			if err = settleRewardRow(ctx, tx, w, "failed", reason, w.detail.Amount, now); err != nil {
				return n, err
			}
			n++
			continue
		}
		if paidToday+amount > t.DailyCredits {
			break // today's total is reached: the rest waits for tomorrow
		}
		paid, err := s.payReviewReward(ctx, tx, w, amount, now)
		if err != nil {
			return n, err
		}
		if paid == "pool" {
			break // the grant pool is dry today
		}
		if paid == "paid" {
			paidToday += amount
			n++
		}
	}
	return n, nil
}

// rewardsPaidOn is the credits review rewards paid on a UTC day.
func rewardsPaidOn(ctx context.Context, q allowance.Querier, day int64) (int64, error) {
	var n int64
	err := q.QueryRowContext(ctx, "SELECT coalesce(sum(amount),0) FROM ledger_entries WHERE day=? AND kind='grant' AND op=?", day, ReviewRewardOp).Scan(&n)
	return n, err
}

// rewardOutcome checks a due reward against the board as it stands: the
// amount to pay, or the public reason it is cancelled. It reads the
// reviewer's current review of the subject (the reward's own, or a newer
// version): both must be visible, the current one a community review whose
// relationship and verified evidence still qualify, and the reviewer must
// not own the subject or share a root with its owner. A newer review with
// weaker evidence pays at its own class's factor, never more than promised.
func (s *Store) rewardOutcome(ctx context.Context, tx *sql.Tx, t rewardTerms, w reviewRewardRow, now int64) (int64, string, error) {
	var hidden bool
	if err := tx.QueryRowContext(ctx, "SELECT hidden<>0 FROM events WHERE id=?", w.eventID).Scan(&hidden); err != nil {
		return 0, "", err
	}
	if hidden {
		return 0, "review_hidden", nil
	}
	var current, rel, raised, class string
	err := tx.QueryRowContext(ctx, `SELECT r.event_id,r.relationship,r.relationship_raised,r.evidence_class,e.hidden<>0 FROM reviews r JOIN events e ON e.id=r.event_id
 WHERE r.subject=? AND r.account=? AND r.current=1`, w.subject, w.account).Scan(&current, &rel, &raised, &class, &hidden)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, "superseded_not_eligible", nil
	}
	if err != nil {
		return 0, "", err
	}
	if hidden {
		return 0, "review_hidden", nil
	}
	if raised != "" {
		rel = raised
	}
	newer := current != w.eventID
	switch {
	case rel == "lab" || rel == "outside_source":
		return 0, "superseded_not_eligible", nil
	case rel == "owner":
		return 0, "affiliated", nil
	case barredRelationship(rel):
		return 0, "relationship", nil
	}
	factor := t.EvidenceFactorsPPM[class]
	var verified bool
	if err = tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM review_evidence WHERE event_id=? AND class=? AND state='verified' AND json_extract(detail,'$.counted_for') IS NULL)", current, class).Scan(&verified); err != nil {
		return 0, "", err
	}
	if factor <= 0 || !verified {
		if newer {
			return 0, "superseded_not_eligible", nil
		}
		return 0, "evidence_not_verified", nil
	}
	root, err := s.accountRoot(ctx, tx, w.account, now)
	if err != nil {
		return 0, "", err
	}
	shared, err := s.sharesOwnerRoot(ctx, tx, w.subject, w.account, root, now)
	if err != nil {
		return 0, "", err
	}
	if shared {
		return 0, "affiliated", nil
	}
	taken, err := s.rootRewarded(ctx, tx, w, root, now)
	if err != nil {
		return 0, "", err
	}
	if taken {
		return 0, "already_rewarded", nil
	}
	amount := w.detail.Amount
	if factor < w.detail.FactorPPM {
		amount = min(amount, rewardAmount(w.detail.BaseCredits, factor, w.detail.VPPM))
	}
	if amount <= 0 {
		return 0, "superseded_not_eligible", nil
	}
	return amount, "", nil
}

// rootRewarded reports whether another account sharing root (the
// reviewer's root now: a domain link may have joined accounts since the
// offer) holds a reward for the subject that is pending or paid. The one
// that settles first keeps it.
func (s *Store) rootRewarded(ctx context.Context, tx *sql.Tx, w reviewRewardRow, root string, now int64) (bool, error) {
	list, err := subjectRewards(ctx, tx, w.subject)
	if err != nil {
		return false, err
	}
	for _, o := range list {
		if o.account == w.account || o.state == "failed" {
			continue
		}
		r, err := s.accountRoot(ctx, tx, o.account, now)
		if err != nil {
			return false, err
		}
		if r == root || o.detail.Root == root {
			return true, nil
		}
	}
	return false, nil
}

// payReviewReward mints the reward from the grant pool and marks it paid,
// in one savepoint: "paid", "pool" when the pool is dry today, or "wait"
// when this account cannot take it now (it stays pending).
func (s *Store) payReviewReward(ctx context.Context, tx *sql.Tx, w reviewRewardRow, amount, now int64) (string, error) {
	if _, err := tx.ExecContext(ctx, "SAVEPOINT review_reward"); err != nil {
		return "", err
	}
	undo := func() error {
		if _, err := tx.ExecContext(ctx, "ROLLBACK TO review_reward"); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, "RELEASE review_reward")
		return err
	}
	if err := settleRewardRow(ctx, tx, w, "verified", "", amount, now); err != nil {
		return "", errors.Join(err, undo())
	}
	reason := fmt.Sprintf("review reward: %d credits for review %s of %s (%s evidence)", amount, w.eventID, w.subject, w.detail.Class)
	err := s.ledger.led.MintRef(ctx, tx, w.account, allowance.Credit, allowance.Granted, amount, reason, ledger.Ref{Service: "reviews", Op: ReviewRewardOp, PublicRef: w.eventID}, now)
	var refusal *allowance.Err
	if errors.As(err, &refusal) {
		if err := undo(); err != nil {
			return "", err
		}
		if refusal.Code == "global_quota_exhausted" {
			return "pool", nil
		}
		slog.Warn("reviews: a reward waits", "review", w.eventID, "code", refusal.Code)
		return "wait", nil
	}
	if err != nil {
		return "", errors.Join(err, undo())
	}
	_, err = tx.ExecContext(ctx, "RELEASE review_reward")
	return "paid", err
}

// settleRewardRow moves a pending reward row to state (verified: paid,
// failed: cancelled with reason); only a pending row moves, exactly once.
func settleRewardRow(ctx context.Context, tx *sql.Tx, w reviewRewardRow, state, reason string, amount, now int64) error {
	d := w.detail
	d.SettledAt, d.Reason, d.Amount = now, reason, amount
	raw, _ := json.Marshal(d)
	res, err := tx.ExecContext(ctx, "UPDATE review_evidence SET state=?,checked_at=?,detail=? WHERE event_id=? AND evidence=? AND state='unknown'", state, now, string(raw), w.eventID, RewardEvidence)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		return errors.Join(err, fmt.Errorf("reviews: reward %s is no longer pending", w.eventID))
	}
	return nil
}

// ReviewRewardHint is the standing offer on a subject with open slots.
type ReviewRewardHint struct {
	AboutCredits int64  `json:"about_credits"`
	Left         int64  `json:"left"`
	Of           int64  `json:"of"`
	Text         string `json:"text"`
	How          string `json:"how"`
}

// reviewRewardHints are the offers on subject ids (any number, existing or
// not): ids with no slot left, or every id while rewards do not run, are
// left out.
func (s *Store) reviewRewardHints(ctx context.Context, q allowance.Querier, ids []string, now int64) (map[string]ReviewRewardHint, error) {
	out := map[string]ReviewRewardHint{}
	if !s.ReviewsEnabled() || len(ids) == 0 {
		return out, nil
	}
	t, err := s.reviewRewardTerms(ctx, q, now)
	if err != nil || !t.on() {
		return out, err
	}
	used := map[string]int64{}
	err = inChunks(ids, func(marks string, args []any) error {
		rows, err := q.QueryContext(ctx, `SELECT r.subject,count(DISTINCT json_extract(v.detail,'$.root')) FROM reviews r JOIN review_evidence v ON v.event_id=r.event_id AND v.evidence='`+RewardEvidence+`' AND v.state<>'failed'
 WHERE r.subject IN (`+marks+`) AND r.created_at>`+strconv.FormatInt(now-t.WindowDays*86400, 10)+` GROUP BY r.subject`, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			var n int64
			if err = rows.Scan(&id, &n); err != nil {
				return err
			}
			used[id] = n
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	for _, id := range ids {
		if left := t.FirstRoots - used[id]; left > 0 {
			out[id] = ReviewRewardHint{AboutCredits: t.BaseCredits, Left: left, Of: t.FirstRoots, How: "/protocol.md#review-rewards",
				Text: fmt.Sprintf("First reviews with evidence earn about %d credits. %d of %d left.", t.BaseCredits, left, t.FirstRoots)}
		}
	}
	return out, nil
}

// reviewRewardHint is one subject's offer, or nil.
func (s *Store) reviewRewardHint(ctx context.Context, q allowance.Querier, id string, now int64) (*ReviewRewardHint, error) {
	m, err := s.reviewRewardHints(ctx, q, []string{id}, now)
	if h, ok := m[id]; ok {
		return &h, err
	}
	return nil, err
}

// AgentReviewRewards is an account's review rewards: pending ones, and
// those settled in the last week, newest first.
type AgentReviewRewards struct {
	Pending        int64          `json:"pending"`
	PendingCredits int64          `json:"pending_credits"`
	Items          []ReviewReward `json:"items"`
	HasMore        bool           `json:"has_more"`
}

// agentRewardsShown bounds AgentReviewRewards.Items.
const agentRewardsShown = 10

// agentReviewRewards reads an account's review rewards through q (its
// reviews by reviews_account); nil while REVIEWS is off or it has none.
func (s *Store) agentReviewRewards(ctx context.Context, q allowance.Querier, account string, now int64) (*AgentReviewRewards, error) {
	if !s.ReviewsEnabled() {
		return nil, nil
	}
	rows, err := q.QueryContext(ctx, "SELECT "+reviewRewardColumns+" FROM reviews r JOIN review_evidence v ON v.event_id=r.event_id AND v.evidence=? WHERE r.account=? AND (v.state='unknown' OR v.checked_at>?) ORDER BY r.created_at DESC, r.event_id",
		RewardEvidence, account, now-7*86400)
	if err != nil {
		return nil, err
	}
	list, err := scanReviewRewards(rows)
	if err != nil || len(list) == 0 {
		return nil, err
	}
	out := &AgentReviewRewards{Items: []ReviewReward{}}
	for _, w := range list {
		if w.state == "unknown" {
			out.Pending++
			out.PendingCredits += w.detail.Amount
		}
		if len(out.Items) < agentRewardsShown {
			r := w.detail.reward(w.state, w.eventID)
			r.Subject = w.subject
			out.Items = append(out.Items, *r)
		} else {
			out.HasMore = true
		}
	}
	return out, nil
}

// reviewRewardStats adds the rewards' public counts and credits to the
// stats operation's map: paid and pending, in all and by evidence class,
// and cancelled. Never split by who reviewed. Nothing while REVIEWS is off.
func (s *Store) reviewRewardStats(ctx context.Context, tx *sql.Tx, stats map[string]int64) error {
	if !s.ReviewsEnabled() {
		return nil
	}
	rows, err := tx.QueryContext(ctx, "SELECT state,coalesce(json_extract(detail,'$.class'),''),count(*),coalesce(sum(json_extract(detail,'$.amount')),0) FROM review_evidence WHERE evidence=? GROUP BY 1,2", RewardEvidence)
	if err != nil {
		return err
	}
	defer rows.Close()
	for _, st := range []string{"paid", "pending"} {
		stats["review_rewards_"+st], stats["review_rewards_"+st+"_credits"] = 0, 0
	}
	stats["review_rewards_cancelled"] = 0
	for rows.Next() {
		var state, class string
		var n, credits int64
		if err = rows.Scan(&state, &class, &n, &credits); err != nil {
			return err
		}
		st := rewardStates[state]
		if st == "cancelled" {
			stats["review_rewards_cancelled"] += n
			continue
		}
		stats["review_rewards_"+st] += n
		stats["review_rewards_"+st+"_credits"] += credits
		if slices.Contains(rewardClasses, class) {
			stats["review_rewards_"+st+"_"+class] += n
			stats["review_rewards_"+st+"_credits_"+class] += credits
		}
	}
	return rows.Err()
}

// reviewRewardsCapabilities is /capabilities reviews.rewards.
func (s *Store) reviewRewardsCapabilities(ctx context.Context) map[string]any {
	now := s.now().Unix()
	t, err := s.reviewRewardTerms(ctx, s.db, now)
	if err != nil {
		return map[string]any{"error": "parameters unavailable"}
	}
	classes := make([]string, 0, len(t.EvidenceFactorsPPM))
	for c := range t.EvidenceFactorsPPM {
		classes = append(classes, c)
	}
	sort.Strings(classes)
	out := map[string]any{
		"on": t.on(), "params": t.reviewRewardsParams, "params_version": t.version, "namespace": ReviewRewardsParamsNamespace, "params_url": "/api/params/" + ReviewRewardsParamsNamespace,
		"amount":   "base_credits × evidence factor × v(standing) (1 for a reviewer with a visible public post a day old when it reviewed), whole credits; the verdict never changes it and votes never pay",
		"eligible": "a current, visible community review (not lab or outside_source) whose class, from verified evidence only, has a factor (" + fmt.Sprint(classes) + "); relationship not owner, affiliate or paid; the reviewer's root not the subject owner's root; v(standing) above 0",
		"coverage": fmt.Sprintf("once per root per subject; only the first %d independent roots of a subject in %d days", t.FirstRoots, t.WindowDays),
		"caps":     map[string]any{"per_account_per_day": t.PerAccountPerDay, "per_subject_per_day": t.PerSubjectPerDay, "daily_credits": t.DailyCredits, "source": "the day's credit grant pool (tier 0); never minted outside it"},
		"hold":     fmt.Sprintf("pending for %d hours, then paid as granted credit (ledger op %s, ref the review id) unless the review was hidden, superseded by one that does not qualify, its evidence is no longer verified or the reviewer is found affiliated (cancelled with that reason)", t.HoldHours, ReviewRewardOp),
		"receipt":  "a review's write receipt carries reward {state pending, amount, due_at}, {state none, reason}, or {state pending_evidence, evidence pending, pending_evidence [ids]} while a tx: payment is still read on Base (the review card's reward shows the outcome)",
		"offer":    "subject.get data.review_reward and find results' review_reward while a subject has slots left",
		"stats":    "/api/stats review_rewards_*",
		"docs":     "/protocol.md#review-rewards",
	}
	if !t.on() {
		out["off"], out["note"] = t.off, rewardOffNotes[t.off]
	}
	return out
}

// ReviewRewardStats is reviewRewardStats on its own read, for the /stats
// page; nil while REVIEWS is off.
func (s *Store) ReviewRewardStats(ctx context.Context) (map[string]int64, error) {
	if !s.ReviewsEnabled() {
		return nil, nil
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	stats := map[string]int64{}
	return stats, s.reviewRewardStats(ctx, tx, stats)
}
