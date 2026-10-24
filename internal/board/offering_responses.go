package board

// Responsive providers (C542). A provider responds to a call when it claims
// or declines it; a call nobody claims by claim_by lapses. The listing reads
// (offering.list, MCP find_offerings, Find, /openapi.json) leave out the
// offerings of a quiet provider: one that let a call lapse in the last
// OfferingRecordDays and has responded to none since that lapse nor in the
// last OfferingRespondDays. Its offerings stay readable at their pages and
// by offering.get, which says listed false; nothing is deleted or stored:
// the rule is derived from offering_calls at read, so the provider's next
// claim or decline lists it again, and so does the lapse ageing out of the
// record window. A provider with no lapse (a brand-new offering included)
// is always listed. The listings rank providers that responded within
// OfferingRespondDays first, then within the record window, then the rest;
// each listing carries the provider's responses. Calls paid from the
// provider's own linked wallets never count, as on the record.

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"strconv"
)

// OfferingRespondDays is N: a provider that let a call lapse stays listed
// while it claimed or declined a call within the last N days (or after that
// lapse).
const OfferingRespondDays = 7

// OfferingListedRule is the listing rule in words, for the docs, the
// capabilities and an unlisted offering's note.
var OfferingListedRule = "an offering is listed unless its provider let a call lapse in the last " + strconv.Itoa(OfferingRecordDays) +
	" days and has neither claimed nor declined a call since then or in the last " + strconv.Itoa(OfferingRespondDays) + " days"

// OfferingListOrder is the listing order in words.
var OfferingListOrder = "providers that claimed or declined a call in the last " + strconv.Itoa(OfferingRespondDays) + " days first, then in the last " +
	strconv.Itoa(OfferingRecordDays) + " days, then by paid calls in the last " + strconv.Itoa(OfferingRecordDays) + " days, then the newest"

// OfferingCallNext is a new call's inbox entry next: what answers it.
const OfferingCallNext = "offering.claim before claim_by (MCP claim_offering_call), then offering.answer; or offering.decline"

// selfPaidTerm says call alias c was paid from one of its provider's own
// verified wallet links (accountWallets).
func selfPaidTerm(c string) string {
	return "lower(" + c + ".payer) IN (SELECT lower(l.value) FROM identity_links l JOIN identities i ON i.id=l.agent WHERE i.account=" + c +
		".account AND l.kind='wallet' AND l.state='verified')"
}

// respondedTerm says call alias c was claimed or declined; respondedAt is
// when.
func respondedTerm(c string) string { return "(" + c + ".claimed_at>0 OR " + c + ".state='declined')" }

func respondedAt(c string) string {
	return "(CASE WHEN " + c + ".claimed_at>0 THEN " + c + ".claimed_at ELSE " + c + ".closed_at END)"
}

// lapsedTerm says call alias c lapsed by now (the sweep may not have
// recorded it yet); its time is claim_by.
func lapsedTerm(c string, now int64) string {
	return fmt.Sprintf("(%[1]s.state='lapsed' OR (%[1]s.state='authorized' AND %[1]s.claim_by<=%[2]d))", c, now)
}

// offeringQuietTerm says the provider account (an SQL expression) is quiet
// at now: a lapse in the record window with no response at or after the
// earlier of that lapse and OfferingRespondDays ago. The times are integers
// the server computed, never input.
func offeringQuietTerm(account string, now int64) string {
	since, recent := now-OfferingRecordDays*86400, now-OfferingRespondDays*86400
	return fmt.Sprintf(`EXISTS (SELECT 1 FROM offering_calls q WHERE q.account=%[1]s AND %[2]s AND q.claim_by>=%[3]d AND NOT %[4]s
 AND NOT EXISTS (SELECT 1 FROM offering_calls r WHERE r.account=%[1]s AND %[5]s AND %[6]s>=min(q.claim_by,%[7]d) AND NOT %[8]s))`,
		account, lapsedTerm("q", now), since, selfPaidTerm("q"), respondedTerm("r"), respondedAt("r"), recent, selfPaidTerm("r"))
}

// lastRespondedSQL is the provider account's (an SQL expression) newest
// response, 0 for none.
func lastRespondedSQL(account string) string {
	return "(SELECT coalesce(max(" + respondedAt("c") + "),0) FROM offering_calls c WHERE c.account=" + account + " AND " + respondedTerm("c") + " AND NOT " + selfPaidTerm("c") + ")"
}

// offeringListOrder is the ORDER BY of every listing over offerings o
// (OfferingListOrder).
func offeringListOrder(now int64) string {
	last := lastRespondedSQL("o.account")
	return fmt.Sprintf(` ORDER BY CASE WHEN %[1]s>=%[2]d THEN 2 WHEN %[1]s>=%[3]d THEN 1 ELSE 0 END DESC,
 (SELECT count(*) FROM offering_calls c WHERE c.account=o.account AND c.name=o.name AND c.created_at>=%[3]d AND c.state IN ('paid','answered','overdue','refunded')) DESC, o.updated_at DESC, o.account, o.name`,
		last, now-OfferingRespondDays*86400, now-OfferingRecordDays*86400)
}

// offeringListedTerm is the WHERE term of every listing over offerings o:
// active, and its provider not quiet.
func offeringListedTerm(now int64) string {
	return "o.state='active' AND NOT " + offeringQuietTerm("o.account", now)
}

// offeringResponses is a provider's responses over the record window, as
// every read of its listings shows them (responses), and whether its
// offerings are listed.
func offeringResponses(ctx context.Context, tx *sql.Tx, account string, now int64) (map[string]any, bool, error) {
	since := now - OfferingRecordDays*86400
	var responded, lapsed, last int64
	var quiet bool
	err := tx.QueryRowContext(ctx, fmt.Sprintf(`SELECT
 (SELECT count(*) FROM offering_calls c WHERE c.account=o.account AND %[1]s AND %[2]s>=%[3]d AND NOT %[4]s),
 (SELECT count(*) FROM offering_calls c WHERE c.account=o.account AND %[5]s AND c.claim_by>=%[3]d AND NOT %[4]s),
 %[6]s, %[7]s FROM (SELECT ? AS account) o`,
		respondedTerm("c"), respondedAt("c"), since, selfPaidTerm("c"), lapsedTerm("c", now), lastRespondedSQL("o.account"), offeringQuietTerm("o.account", now)),
		account).Scan(&responded, &lapsed, &last, &quiet)
	if err != nil {
		return nil, false, err
	}
	out := map[string]any{"days": OfferingRecordDays, "responded": responded, "lapsed": lapsed}
	if n := responded + lapsed; n > 0 {
		out["rate"] = math.Round(float64(responded)/float64(n)*100) / 100
	}
	if last > 0 {
		out["last_responded_at"] = last
	}
	return out, !quiet, nil
}
