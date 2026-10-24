package board

// tx: review evidence checked on chain (RFC 0015 §5.2, C248). A direct
// x402 or MPP purchase paid on Base from one of the reviewer's verified
// linked wallets is paid use. When the review is posted the board only
// checks what it holds (the chain is Base, the subject is an x402 or MPP
// endpoint, its pay_to is known) and records the row unknown, reason
// tx_pending. After commit the lab-record worker (reviews_records.go) reads
// the transaction through the work.settle chain reader (WORK_USDC_RPC_URL,
// services.USDCChain), holding no transaction across the network call, then
// writes verified or failed in one short transaction. A verified row raises
// the review's class and may offer its reward. Without a chain reader the
// row stays unknown, unchecked, as before.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"math/big"
	"strings"

	"swarmmemo/internal/reviews"
	"swarmmemo/internal/services"
)

const (
	txEvidencePrefix = "tx:"
	// txEvidenceEnd bounds the tx: rows of a review_evidence range.
	txEvidenceEnd = "tx;"
	// TxPending is a tx: row's reason while it waits to be read on chain.
	TxPending = "tx_pending"
	// txUnchecked is a tx: row's reason while no chain reader is configured.
	txUnchecked = "on-chain payments are not checked yet"
	// reviewTxRetry is how long a tx: row waits between reads that found it
	// not yet mined, not yet confirmed or the chain unreachable.
	reviewTxRetry = 60
	// reviewTxNotFoundAfter is how long after the review a transaction
	// nobody mined fails as tx_not_found.
	reviewTxNotFoundAfter = 86400
)

// checkTxEvidence is the posting transaction's part of a tx: check: point
// reads only, no network.
func (s *Store) checkTxEvidence(ctx context.Context, tx *sql.Tx, sub reviews.Subject, value string, row *reviewEvidenceRow) error {
	row.class = "paid_use"
	cfg := s.config.WorkUSDC
	if cfg == nil {
		row.state, row.detail["reason"] = "unknown", txUnchecked
		return nil
	}
	i := strings.LastIndex(value, ":")
	if i < 0 || value[:i] != cfg.Network {
		row.fail("tx_not_on_base")
		return nil
	}
	if sub.Type != reviews.TypeX402 && sub.Type != reviews.TypeMPP {
		row.fail("not_an_x402_or_mpp_subject")
		return nil
	}
	payTo, source, ok, err := s.subjectPayTo(ctx, tx, sub)
	if err != nil {
		return err
	}
	if !ok {
		row.fail("subject_pay_to_unknown")
		return nil
	}
	row.state = "unknown"
	row.detail = map[string]any{"reason": TxPending, "pay_to": payTo.String(), "pay_to_source": source}
	return nil
}

// subjectPayTo is the address an x402 or MPP subject's 402 names: its
// offering's pay_to on this board, a pinned resource's, else the vetted or
// open catalogue's (the most recently seen row). ok is false when no
// record of the subject names one.
func (s *Store) subjectPayTo(ctx context.Context, tx *sql.Tx, sub reviews.Subject) (services.EVMAddress, string, bool, error) {
	opt := s.subjectOptions()
	parse := func(v string) (services.EVMAddress, bool) { return services.ParseEVMAddress(strings.ToLower(v)) }
	if account, _, name, ok, err := offeringOwner(ctx, tx, sub, opt); err != nil || ok {
		if err != nil {
			return services.EVMAddress{}, "", false, err
		}
		var v string
		if err = tx.QueryRowContext(ctx, "SELECT pay_to FROM offerings WHERE account=? AND name=?", account, name).Scan(&v); err != nil && !errors.Is(err, sql.ErrNoRows) {
			return services.EVMAddress{}, "", false, err
		}
		a, ok := parse(v)
		return a, "offering", ok, nil
	}
	if cfg := s.config.X402; cfg != nil {
		for _, r := range cfg.Resources {
			if r.PayTo != (services.EVMAddress{}) && subjectMatchesURL(sub, r.Method, r.URL, opt) {
				return r.PayTo, "x402_resource", true, nil
			}
		}
	}
	host := sub.Host()
	if host == "" {
		return services.EVMAddress{}, "", false, nil
	}
	rows, err := tx.QueryContext(ctx, `SELECT url,method,pay_to,'x402_vetted' FROM (SELECT url,method,pay_to FROM x402_vetted WHERE instr(lower(url),?1)>0 ORDER BY changed_at DESC LIMIT 128)
 UNION ALL SELECT url,method,pay_to,'x402_catalogue' FROM (SELECT url,method,pay_to FROM x402_catalogue WHERE instr(lower(url),?1)>0 ORDER BY last_seen DESC LIMIT 128)`, "://"+host)
	if err != nil {
		return services.EVMAddress{}, "", false, err
	}
	defer rows.Close()
	for rows.Next() {
		var u, m, p, source string
		if err = rows.Scan(&u, &m, &p, &source); err != nil {
			return services.EVMAddress{}, "", false, err
		}
		if a, ok := parse(p); ok && subjectMatchesURL(sub, m, u, opt) {
			return a, source, true, nil
		}
	}
	return services.EVMAddress{}, "", false, rows.Err()
}

// pendingTx is one tx: row waiting to be read on chain, with its review.
type pendingTx struct {
	eventID, evidence, account, subject string
	createdAt                           int64
}

// verifyReviewTxs reads up to a batch of pending tx: rows on chain and
// settles them, and reports how many it read. The rows are read and the
// pool released before any network call; each row's outcome is one short
// transaction.
func (s *Store) verifyReviewTxs(ctx context.Context) (int, error) {
	cfg := s.config.WorkUSDC
	if cfg == nil {
		return 0, nil
	}
	now := s.now().Unix()
	rows, err := s.db.QueryContext(ctx, `SELECT v.event_id,v.evidence,r.account,r.subject,r.created_at FROM review_evidence v JOIN reviews r ON r.event_id=v.event_id
 WHERE v.state='unknown' AND v.evidence>=? AND v.evidence<? AND json_extract(v.detail,'$.reason')=? AND (coalesce(json_extract(v.detail,'$.attempts'),0)=0 OR v.checked_at<=?)
 ORDER BY v.checked_at,v.event_id LIMIT ?`, txEvidencePrefix, txEvidenceEnd, TxPending, now-reviewTxRetry, reviewRecordBatch)
	if err != nil {
		return 0, err
	}
	var batch []pendingTx
	for rows.Next() {
		var p pendingTx
		if err = rows.Scan(&p.eventID, &p.evidence, &p.account, &p.subject, &p.createdAt); err != nil {
			rows.Close()
			return 0, err
		}
		batch = append(batch, p)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return 0, err
	}
	for _, p := range batch {
		hash := p.evidence[strings.LastIndex(p.evidence, ":")+1:]
		t, lookupErr := cfg.Lookup(ctx, s.webhookDial, hash)
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		if err = s.settleReviewTx(ctx, p, t, lookupErr); err != nil {
			return 0, err
		}
	}
	return len(batch), nil
}

// settleReviewTx writes what the chain said about one tx: row, in its own
// transaction: verified, failed with a reason, or still pending (attempts
// counted, read again after reviewTxRetry).
func (s *Store) settleReviewTx(ctx context.Context, p pendingTx, t services.USDCTx, lookupErr error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := s.now().Unix()
	var raw string
	err = tx.QueryRowContext(ctx, "SELECT detail FROM review_evidence WHERE event_id=? AND evidence=? AND state='unknown'", p.eventID, p.evidence).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil // settled meanwhile
	}
	if err != nil {
		return err
	}
	detail := map[string]any{}
	_ = json.Unmarshal([]byte(raw), &detail)
	state, out, err := s.reviewTxOutcome(ctx, tx, p, detail, t, lookupErr, now)
	if err != nil {
		return err
	}
	b, _ := json.Marshal(out)
	if _, err = tx.ExecContext(ctx, "UPDATE review_evidence SET state=?,checked_at=?,detail=? WHERE event_id=? AND evidence=? AND state='unknown'", state, now, string(b), p.eventID, p.evidence); err != nil {
		return err
	}
	if state == "verified" {
		if err = s.raiseReviewClass(ctx, tx, p.eventID, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// reviewTxOutcome checks a transaction read on chain against the review:
// it succeeded and is confirmed; it was mined within ReviewEvidenceDays
// before the review (and not after it); it carries a USDC transfer of more
// than zero to the subject's pay_to from one of the reviewer's verified
// linked wallets, none of them the provider's own; and no other account's
// review of the subject already counts it.
func (s *Store) reviewTxOutcome(ctx context.Context, tx *sql.Tx, p pendingTx, detail map[string]any, t services.USDCTx, lookupErr error, now int64) (string, map[string]any, error) {
	keep := map[string]any{"pay_to": detail["pay_to"], "pay_to_source": detail["pay_to_source"]}
	fail := func(reason string) (string, map[string]any, error) {
		keep["reason"] = reason
		return "failed", keep, nil
	}
	retry := func() (string, map[string]any, error) {
		n, _ := detail["attempts"].(float64)
		detail["attempts"] = int64(n) + 1
		return "unknown", detail, nil
	}
	var ce *services.ChainError
	switch {
	case errors.As(lookupErr, &ce) && ce.Code == "usdc_tx_not_found":
		if now-p.createdAt > reviewTxNotFoundAfter {
			return fail("tx_not_found")
		}
		return retry()
	case lookupErr != nil:
		return retry()
	case !t.Success:
		return fail("tx_failed")
	case t.Confirmations < s.config.WorkUSDC.Confirmations:
		return retry()
	case t.BlockTime < p.createdAt-ReviewEvidenceDays*86400:
		return fail("older_than_30_days")
	case t.BlockTime > p.createdAt+ReviewRecordAsOfSkew:
		return fail("tx_after_the_review")
	}
	payTo, ok := services.ParseEVMAddress(strings.ToLower(asString(detail["pay_to"])))
	if !ok {
		return fail("subject_pay_to_unknown")
	}
	mine, err := accountWallets(ctx, tx, p.account)
	if err != nil {
		return "", nil, err
	}
	paid, payers := new(big.Int), map[services.EVMAddress]bool{}
	toPayee, fromMine := false, false
	for _, tr := range t.Transfers {
		if tr.To != payTo {
			continue
		}
		toPayee = true
		if !mine[tr.From] {
			continue
		}
		fromMine = true
		if tr.Value.Sign() > 0 {
			paid.Add(paid, tr.Value)
			payers[tr.From] = true
		}
	}
	switch {
	case !toPayee:
		return fail("tx_not_to_the_subjects_pay_to")
	case !fromMine:
		return fail("tx_not_from_your_wallet")
	case paid.Sign() == 0:
		return fail("tx_amount_zero")
	}
	sub, found, err := lookupSubject(ctx, tx, p.subject)
	if err != nil {
		return "", nil, err
	}
	provider := map[services.EVMAddress]bool{payTo: true}
	if found {
		owners, err := s.subjectOwners(ctx, tx, sub)
		if err != nil {
			return "", nil, err
		}
		for _, o := range owners {
			w, err := accountWallets(ctx, tx, o.Account)
			if err != nil {
				return "", nil, err
			}
			for a := range w {
				provider[a] = true
			}
		}
	}
	for a := range payers {
		if provider[a] {
			return fail("paid_from_the_providers_wallet")
		}
	}
	var cited bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM review_evidence v JOIN reviews r ON r.event_id=v.event_id
 WHERE v.evidence=? AND v.state='verified' AND r.subject=? AND r.account<>?)`, p.evidence, p.subject, p.account).Scan(&cited); err != nil {
		return "", nil, err
	}
	if cited {
		return fail("tx_cited_by_another_review")
	}
	amount := paid.String()
	if paid.IsInt64() {
		amount = services.FormatUSDC(paid.Int64())
	}
	keep["day"] = t.BlockTime - t.BlockTime%86400
	keep["block"] = t.Block
	keep["amount"] = amount
	keep["funded"] = "paid"
	return "verified", keep, nil
}

func asString(v any) string { s, _ := v.(string); return s }

// raiseReviewClass sets a review's class to its best verified evidence once
// a row verified after commit, and offers its reward when the review is
// current and visible and holds none yet (offerReviewReward decides).
func (s *Store) raiseReviewClass(ctx context.Context, tx *sql.Tx, eventID string, now int64) error {
	classes, err := stringColumn(ctx, tx, "SELECT class FROM review_evidence WHERE event_id=? AND state='verified' AND json_extract(detail,'$.counted_for') IS NULL", eventID)
	if err != nil {
		return err
	}
	var current, raw, account, raised string
	var seasoned, isCurrent int
	var hidden bool
	var createdAt int64
	err = tx.QueryRowContext(ctx, `SELECT r.evidence_class,r.review,r.account,r.relationship_raised,r.seasoned,r.current,e.hidden<>0,r.created_at FROM reviews r JOIN events e ON e.id=r.event_id WHERE r.event_id=?`, eventID).
		Scan(&current, &raw, &account, &raised, &seasoned, &isCurrent, &hidden, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	best := current
	for _, c := range classes {
		if rankOf(c) > rankOf(best) {
			best = c
		}
	}
	if best == current {
		return nil
	}
	if _, err = tx.ExecContext(ctx, "UPDATE reviews SET evidence_class=? WHERE event_id=?", best, eventID); err != nil {
		return err
	}
	var rewarded bool
	if err = tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM review_evidence WHERE event_id=? AND evidence=?)", eventID, RewardEvidence).Scan(&rewarded); err != nil {
		return err
	}
	if isCurrent != 1 || hidden || rewarded {
		return nil
	}
	r, err := reviews.Parse([]byte(raw), s.subjectOptions())
	if err != nil {
		return nil
	}
	p := &pendingReview{review: r, raw: raw, account: account, seasoned: seasoned == 1, createdAt: createdAt}
	_, err = s.offerReviewReward(ctx, tx, p, eventID, best, raised, now)
	return err
}

func rankOf(class string) int {
	for i, c := range reviewClassRank {
		if c == class {
			return i
		}
	}
	return -1
}
