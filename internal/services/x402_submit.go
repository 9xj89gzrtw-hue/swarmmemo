package services

// Self-serve listing (C299): a seller who verified its domain lists its own
// x402 endpoint in the open catalogue (x402.submit), with no parallel
// catalogue. The board checks the domain ownership (a verified identity
// link on the URL's host or registrable domain) and the daily limit; here
// the endpoint's unpaid 402 challenge is fetched through the relay's
// SSRF-safe client, never paid, read by the parser the relay uses
// (parseX402Required), turned into a discovery item (x402ChallengeItem) and
// normalised by the one normaliser of crawled items (bazaarItem.resource).
// It is then admitted by the same guardrails (admitOpenWith), checked against
// the same per-recipient and per-domain caps (under which it displaces
// crawled entries, never vetted or submitted ones), and upserted into the same
// table with source "submitted:ACCOUNT". From there it is an open resource
// like any other: a candidate until vetted, its summary screened before it
// is served, ranked after vetted and paid ones but before the discovery
// signal, and re-probed at every refresh (a crawled one is re-read from its
// discovery list); not seen for three refreshes, it is stale. Withdrawing
// (x402.withdraw) is its owner removing it: the row is deleted.
//
// Ownership has two proofs. A verified domain link on the URL's host or
// registrable domain (the board's subjectOwners), or, for sellers on shared
// hosting (workers.dev, vercel.app ...) whose DNS they cannot write, a
// wallet: every option of the challenge on the relay's network pays one of
// the submitter's verified wallet links (the board's accountWallets, as for
// offerings). The money goes to that wallet, so listing it only serves its
// owner. The source records which proof held: submitted:PROOF:ACCOUNT. A
// wallet-proven listing whose challenge later pays anyone else has lost its
// proof: the re-probe marks it stale (kept, not listed).

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"swarmmemo/internal/find"
)

const (
	// x402SubmittedPrefix starts a submitted entry's source; the proof
	// (ProofDomain or ProofWallet), a colon and the submitter's account
	// follow.
	x402SubmittedPrefix = "submitted:"
	// X402SubmitsPerDay is how many submissions (each probes the endpoint)
	// one account makes a UTC day, refused ones included.
	X402SubmitsPerDay = 10
	// x402SubmittedShare: submitted entries fill at most 1/x402SubmittedShare
	// of the catalogue's max_resources, so self-listing never crowds out the
	// crawl.
	x402SubmittedShare = 4
	// X402SummaryBytes bounds a submitted summary, as a crawled one is cut.
	X402SummaryBytes = 200
	// X402PerRecipientMax and X402PerDomainMax are capOpen's caps, as the
	// board's refusal states them.
	X402PerRecipientMax = x402PerRecipientMax
	X402PerDomainMax    = x402PerDomainMax
)

// The ownership proofs of a submitted listing.
const (
	ProofDomain = "domain" // a verified domain link on the URL's host or registrable domain
	ProofWallet = "wallet" // the challenge pays only the submitter's verified wallet links
)

// submittedSource is a submitted entry's source.
func submittedSource(proof, account string) string {
	return x402SubmittedPrefix + proof + ":" + account
}

// submission is r's proof and submitter, "" for a crawled or pinned one.
func (r *X402Resource) submission() (proof, account string) {
	rest, ok := strings.CutPrefix(r.Source, x402SubmittedPrefix)
	if !ok {
		return "", ""
	}
	proof, account, _ = strings.Cut(rest, ":")
	return proof, account
}

// Submitter is the account that listed r (x402.submit), "" for a crawled
// or pinned resource.
func (r *X402Resource) Submitter() string {
	_, account := r.submission()
	return account
}

// Proof is how r's submitter proved it owns it (ProofDomain or
// ProofWallet), "" for a crawled or pinned resource.
func (r *X402Resource) Proof() string {
	proof, _ := r.submission()
	return proof
}

// ErrX402Off refuses a listing while the open catalogue is off.
var ErrX402Off = refusal("x402_listing_off")

// The refusals of a submission beyond the normaliser's (x402_bazaar.go).
var (
	errX402Target      = refusal("x402_listing_target")         // target does not split into METHOD URL at all
	errX402Template    = refusal("x402_listing_path_template")  // a {name} template in the path
	errX402Ephemeral   = refusal("x402_listing_ephemeral_host") // a quick-tunnel host
	errX402Unowned     = refusal("x402_listing_unowned")        // neither a domain link nor the challenge's wallets
	errX402Unreachable = refusal("x402_listing_unreachable")    // no answer
	errX402NoChallenge = refusal("x402_listing_no_challenge")   // an answer other than an x402 402
	errX402Denied      = refusal("x402_listing_denied")         // the denylist
	errX402Pinned      = refusal("x402_listing_pinned")         // already in the operator's allowlist
	errX402Caps        = refusal("x402_listing_caps")           // caps full of vetted or submitted entries, or the submitted share
	errX402NotListed   = refusal("x402_listing_not_found")      // nothing submitted at that METHOD URL
	errX402Category    = refusal("x402_listing_category")       // not a catalogue category
	errX402Summary     = refusal("x402_listing_summary")        // too long, or not one line of text
)

// X402Submission is one x402.submit: the submitter's account, the
// endpoint, an optional summary and category that replace what the
// challenge says, and what the board found the account owns: Domain when a
// verified domain link covers the URL's host, Wallets its verified wallet
// links (accountWallets).
type X402Submission struct {
	Account, Method, URL string
	Summary, Category    string
	Domain               bool
	Wallets              map[EVMAddress]bool
}

// ParseX402Target reads an x402.submit or x402.withdraw target: METHOD URL,
// GET or POST and an HTTPS URL on 443 to a public DNS name, as the
// catalogue admits (checkX402URL, the same check the Bazaar normaliser
// applies to a crawled item, x402_bazaar.go). It never fetches. target
// itself being unparseable (no METHOD URL split) is errX402Target; a bad
// method and a bad URL get the normaliser's own errX402Method and
// errX402NotHTTP, so there is one validator and one code for each.
func ParseX402Target(target string) (method, rawURL string, err error) {
	method, rawURL, ok := strings.Cut(strings.TrimSpace(target), " ")
	method, rawURL = strings.ToUpper(method), strings.TrimSpace(rawURL)
	if !ok || method == "" || rawURL == "" {
		return "", "", errX402Target
	}
	if method != http.MethodGet && method != http.MethodPost {
		return "", "", errX402Method
	}
	if checkX402URL(rawURL) != nil {
		return "", "", errX402NotHTTP
	}
	return method, rawURL, nil
}

// x402PathTemplate reports whether raw's path holds a template such as
// /ares/{ico}, literal or percent-escaped (%7B, %7D). The relay calls a
// listing's URL as listed, filling query parameters only, so such a path
// is never callable: a submission is refused, a crawled item is not
// admitted, and a row already stored is marked stale (staleBadURL).
func x402PathTemplate(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && strings.ContainsAny(u.Path, "{}")
}

// x402BadURL reports whether raw is never callable (x402PathTemplate) or
// on an ephemeral tunnel host (x402EphemeralHost): the two reasons a
// catalogue row is marked stale rather than kept live.
func x402BadURL(raw string) bool {
	return x402PathTemplate(raw) || x402EphemeralHost(raw)
}

// staleBadURL marks every catalogue row whose URL is bad (x402BadURL: a
// path template or an ephemeral tunnel host) stale (last_seen 0, as an
// unseen row becomes), never deleting it: rows stored before such URLs
// were refused. The SQL only narrows the rows; x402BadURL decides.
func (x *x402) staleBadURL(ctx context.Context) (int, error) {
	like := make([]any, len(X402EphemeralTunnelHosts))
	where := `instr(url,'{')>0 OR instr(url,'}')>0 OR instr(upper(url),'%7B')>0 OR instr(upper(url),'%7D')>0`
	for i, suf := range X402EphemeralTunnelHosts {
		where += " OR instr(url,?)>0"
		like[i] = suf
	}
	type row struct{ id, url, source string }
	rows, err := queryAll(ctx, x.db, func(q *sql.Rows) (row, error) {
		var v row
		return v, q.Scan(&v.id, &v.url, &v.source)
	}, `SELECT id,url,source FROM x402_catalogue WHERE last_seen<>0 AND (`+where+`)`, like...)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, v := range rows {
		if !x402BadURL(v.url) {
			continue
		}
		if _, err = x.db.ExecContext(ctx, "UPDATE x402_catalogue SET last_seen=0 WHERE id=? AND source=?", v.id, v.source); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// CheckX402Submission checks a submission's own text before anything is
// fetched: a concrete path (no template, x402PathTemplate), not an
// ephemeral tunnel host (x402EphemeralHost), a summary of at most
// X402SummaryBytes on one line, a category the catalogue names. A
// withdrawal is never checked here: a listing stored with a template or on
// a tunnel host can still be withdrawn.
func CheckX402Submission(s X402Submission) error {
	if x402PathTemplate(s.URL) {
		return errX402Template
	}
	if x402EphemeralHost(s.URL) {
		return errX402Ephemeral
	}
	if len(s.Summary) > X402SummaryBytes || strings.ContainsAny(s.Summary, "\r\n") || cleanUntrusted(s.Summary, X402SummaryBytes) != strings.Join(strings.Fields(s.Summary), " ") {
		return errX402Summary
	}
	if s.Category != "" && s.Category != "other" && !slices.ContainsFunc(x402Categories, func(c find.Category) bool { return c.Name == s.Category }) {
		return errX402Category
	}
	return nil
}

// x402ChallengeItem is a probed endpoint's 402 challenge as a discovery
// item, so the normaliser reads a submitted endpoint exactly as a crawled
// one: its URL and method are what was probed (an upstream's own resource
// URL is never followed), its options, description and input the
// challenge's.
func x402ChallengeItem(method, rawURL string, req x402Required) bazaarItem {
	it := bazaarItem{Resource: rawURL, Type: "http", X402Version: json.Number(strconv.Itoa(req.Version)), Accepts: req.Accepts, Description: req.Description, Method: method}
	it.Extensions.Bazaar.Info.Input = req.Input
	it.Extensions.Bazaar.Info.Input.Method = method
	return it
}

// probe fetches the endpoint's unpaid 402 challenge through the relay's
// SSRF-safe client (no redirect, no proxy, the catalogue's timeout, the 402
// body bound) and normalises it. It never signs or pays: the request
// carries no payment header. A POST is probed with an empty JSON object.
// It also answers every recipient the challenge names on the relay's
// network, which a wallet proof must all own.
func (x *x402) probe(ctx context.Context, method, rawURL string) (X402Resource, []EVMAddress, error) {
	cc := x.cfg.Catalogue
	p := x402Plan{res: &X402Resource{Method: method, Timeout: cc.Timeout}, url: rawURL}
	if method == http.MethodPost {
		p.body = []byte("{}")
	}
	resp, err := x.fetch(ctx, p, nil, x402RequiredBodyBytes)
	if err != nil {
		return X402Resource{}, nil, errX402Unreachable
	}
	if resp.status != http.StatusPaymentRequired {
		return X402Resource{}, nil, errX402NoChallenge
	}
	if resp.over {
		resp.body = nil // a cut challenge is never parsed
	}
	req, ok := parseX402Required(resp.header.Get(x402V2Required), resp.body)
	if !ok {
		return X402Resource{}, nil, errX402NoChallenge
	}
	it := x402ChallengeItem(method, rawURL, req)
	r, _, err := it.resource(x.cfg, min(cc.MaxPrice, x.cfg.PerCall))
	if err != nil {
		return X402Resource{}, nil, err
	}
	r.ID = openID(r.ID, r.Method, r.URL)
	return r, x.challengePayTos(req), nil
}

// challengePayTos are the recipients of every option of req on the relay's
// network (v1 names mapped to CAIP-2), unparseable ones as the zero
// address, so a wallet proof never skips an option it cannot read.
func (x *x402) challengePayTos(req x402Required) []EVMAddress {
	var out []EVMAddress
	for _, raw := range req.Accepts {
		var q x402Requirement
		if json.Unmarshal(raw, &q) != nil {
			continue
		}
		network := q.Network
		if req.Version == 1 {
			network = x402V1Networks[q.Network]
		}
		if network != x.cfg.Network {
			continue
		}
		payTo, _ := ParseEVMAddress(q.PayTo)
		out = append(out, payTo)
	}
	return out
}

// walletsOwn reports whether every recipient is one of wallets (and there
// is at least one).
func walletsOwn(payTos []EVMAddress, wallets map[EVMAddress]bool) bool {
	for _, p := range payTos {
		if !wallets[p] {
			return false
		}
	}
	return len(payTos) > 0
}

// x402Provider is the x402 provider with an open catalogue, or nil.
func (r *Registry) x402Provider() *x402 {
	p, err := r.Lookup("x402")
	if err != nil {
		return nil
	}
	x, ok := p.(*x402)
	if !ok || x.cfg == nil || x.cfg.Catalogue == nil {
		return nil
	}
	return x
}

// X402Open reports whether the open catalogue takes listings.
func (r *Registry) X402Open() bool { return r.x402Provider() != nil }

// SubmitX402 lists s's endpoint in the open catalogue, or updates its
// listing: probed, normalised, admitted and capped as above, upserted, and
// the snapshot reloaded so Find and the relay see it at once. It runs after
// the board's transaction committed, holding no connection while it
// fetches. It answers the entry as listed.
func (r *Registry) SubmitX402(ctx context.Context, s X402Submission, now int64) (map[string]any, error) {
	x := r.x402Provider()
	if x == nil {
		return nil, ErrX402Off
	}
	if err := CheckX402Submission(s); err != nil {
		return nil, err
	}
	res, payTos, err := x.probe(ctx, s.Method, s.URL)
	if err != nil {
		return nil, err
	}
	proof := ProofDomain
	if !s.Domain {
		if !walletsOwn(payTos, s.Wallets) {
			return nil, errX402Unowned
		}
		proof = ProofWallet
	}
	if s.Summary != "" {
		res.Summary = cleanUntrusted(s.Summary, X402SummaryBytes)
		res.Category = x402Categorize(res.URL + " " + res.Summary)
	}
	if s.Category != "" {
		res.Category = s.Category
	}
	res.Source = submittedSource(proof, s.Account)
	hist, err := x.readHistory(ctx, now)
	if err != nil {
		return nil, err
	}
	idx := x.cfg.denyIndex(hist.denied)
	if !x.cfg.admitOpenWith(&res, idx) {
		if idx.pinned[res.Method+" "+res.canon] {
			return nil, errX402Pinned
		}
		return nil, errX402Denied
	}
	if x.cat.snap.Load() == nil {
		if err = x.loadCatalogue(ctx, now); err != nil {
			return nil, err
		}
	}
	if !x.roomFor(&res) {
		return nil, errX402Caps
	}
	tx, err := x.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	if err = upsertCatalogue(ctx, tx, &res, bazaarSignal{}, now); err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	if err = x.loadCatalogue(ctx, now); err != nil {
		return nil, err
	}
	listed, ok := x.cat.snap.Load().byID[res.ID]
	if !ok || listed.Submitter() != s.Account {
		// Ranked out of the catalogue after all: a refusal stores nothing
		// (a row this submission created goes; an earlier one stays).
		_, _ = x.db.ExecContext(ctx, "DELETE FROM x402_catalogue WHERE id=? AND source=? AND first_seen=?", res.ID, res.Source, now)
		_ = x.loadCatalogue(ctx, now)
		return nil, errX402Caps
	}
	return map[string]any{"listing": x.listingJSON(listed)}, nil
}

// roomFor reports whether r fits the caps capOpen keeps at load: fewer
// than x402PerRecipientMax other vetted or submitted entries to its
// recipient and x402PerDomainMax on its registrable domain (crawled ones
// give way to it), and the submitted share of the catalogue not full. Its
// own earlier listing does not count.
func (x *x402) roomFor(r *X402Resource) bool {
	perPayTo, perDomain, submitted := 0, 0, 0
	for _, o := range x.cat.snap.Load().open {
		if o.ID == r.ID || (!o.Vetted && o.Submitter() == "") {
			continue
		}
		if o.PayTo == r.PayTo {
			perPayTo++
		}
		if o.domain == r.domain {
			perDomain++
		}
		if o.Submitter() != "" {
			submitted++
		}
	}
	return perPayTo < x402PerRecipientMax && perDomain < x402PerDomainMax && submitted < max(1, x.cfg.Catalogue.MaxResources/x402SubmittedShare)
}

// listingJSON is a submitted entry as x402.submit answers it.
func (x *x402) listingJSON(r *X402Resource) map[string]any {
	query := r.Query
	if query == nil {
		query = []string{}
	}
	return map[string]any{
		"id": r.ID, "kind": KindX402, "method": r.Method, "url": r.URL, "pay_to": r.PayTo.String(), "network": x.cfg.Network,
		"max_price": formatUnits(min(r.MaxAmount, x.cfg.PerCall), x.cfg.Decimals), "query": query, "body": r.Body,
		"category": r.Category, "summary": r.Summary, "summary_status": r.summaryStatus, "source": "submitted", "proof": r.Proof(),
		"vetted": r.Vetted, "callable": x.callable(r), "subject": "x402:" + r.Method + " " + r.URL,
	}
}

// WithdrawX402 removes the submitted listing of METHOD URL: the
// submitter's own, or any submitted one when owner (the board found the
// caller owns its domain now). A crawled entry is not the caller's to
// remove; a discovery list that names the endpoint brings it back as
// crawled at the next refresh.
func (r *Registry) WithdrawX402(ctx context.Context, account, method, rawURL string, owner bool, now int64) (map[string]any, error) {
	x := r.x402Provider()
	if x == nil {
		return nil, ErrX402Off
	}
	id := openID(x402Slug(rawURL), method, rawURL)
	query, args := "DELETE FROM x402_catalogue WHERE id=? AND url=? AND method=? AND substr(source,1,?)=?", []any{id, rawURL, method, len(x402SubmittedPrefix), x402SubmittedPrefix}
	if !owner {
		query, args = query+" AND source IN (?,?)", append(args, submittedSource(ProofDomain, account), submittedSource(ProofWallet, account))
	}
	res, err := x.db.ExecContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, errX402NotListed
	}
	if err = x.loadCatalogue(ctx, now); err != nil {
		return nil, err
	}
	return map[string]any{"withdrawn": map[string]any{"id": id, "method": method, "url": rawURL}}, nil
}

// reprobeSubmitted re-reads every submitted entry's 402 challenge at the
// refresh, longest unseen first, until ctx ends: one still payable is
// upserted as seen now (a changed recipient unbinds its vetting, as for a
// crawled one); one that no longer answers with a challenge we can pay is
// left as it was, and is stale after three refreshes. A wallet-proven entry
// whose challenge now pays anyone but the recipient it was proven with has
// lost its only proof: it is removed, and its owner may submit again. One
// short transaction per entry, none held while a probe runs.
func (x *x402) reprobeSubmitted(ctx context.Context, now int64) (int, error) {
	cc := x.cfg.Catalogue
	if cc == nil {
		return 0, nil
	}
	type row struct{ id, method, url, summary, category, source, payTo string }
	rows, err := queryAll(ctx, x.db, func(q *sql.Rows) (row, error) {
		var v row
		return v, q.Scan(&v.id, &v.method, &v.url, &v.summary, &v.category, &v.source, &v.payTo)
	}, "SELECT id,method,url,summary,category,source,pay_to FROM x402_catalogue WHERE substr(source,1,?)=? ORDER BY last_seen,id LIMIT ?",
		len(x402SubmittedPrefix), x402SubmittedPrefix, max(1, cc.MaxResources/x402SubmittedShare))
	if err != nil {
		return 0, err
	}
	n, err := x.staleBadURL(ctx)
	if err != nil {
		return n, err
	}
	for _, v := range rows {
		if ctx.Err() != nil {
			break
		}
		if x402BadURL(v.url) {
			continue // marked stale above, never probed
		}
		r, payTos, err := x.probe(ctx, v.method, v.url)
		if err != nil {
			continue
		}
		r.Summary, r.Category, r.Source = v.summary, v.category, v.source
		if proven, _ := ParseEVMAddress(v.payTo); r.Proof() == ProofWallet && !walletsOwn(payTos, map[EVMAddress]bool{proven: true}) {
			// The proof no longer holds: the row is marked stale at once (as
			// an unseen crawled one becomes), never deleted; the owner may
			// resubmit or withdraw.
			if _, err = x.db.ExecContext(ctx, "UPDATE x402_catalogue SET last_seen=0 WHERE id=? AND source=?", v.id, v.source); err != nil {
				return n, err
			}
			n++
			continue
		}
		tx, err := x.db.BeginTx(ctx, nil)
		if err != nil {
			return n, err
		}
		if err = upsertCatalogue(ctx, tx, &r, bazaarSignal{}, now); err != nil {
			_ = tx.Rollback()
			return n, err
		}
		if err = tx.Commit(); err != nil {
			return n, err
		}
		n++
	}
	if n == 0 {
		return 0, nil
	}
	return n, x.loadCatalogue(context.WithoutCancel(ctx), now)
}
