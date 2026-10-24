package board

// Self-serve paid API listings (C299): x402.submit and x402.withdraw. A
// seller lists its own x402 endpoint in the open catalogue, the one the
// Bazaar crawl feeds (services/x402_submit.go). Here, in the command's
// transaction: the signature, the target, the daily limit (counted in
// audit) and what the account owns: a verified domain link on the URL's
// host or registrable domain, as subjectOwners decides it for reviews, else
// its verified wallet links (accountWallets, as offering.publish's pay_to);
// with neither, it is refused at once. After commit, holding no connection:
// the probe, the wallet proof (the challenge pays only those wallets), the
// guardrails and the upsert.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"swarmmemo/internal/reviews"
	"swarmmemo/internal/services"
)

// x402SubmitData is x402.submit's optional data.
type x402SubmitData struct {
	Schema   int    `json:"schema"`
	Summary  string `json:"summary,omitempty"`
	Category string `json:"category,omitempty"`
}

// auditX402Listed is the audit operation of a submission that was listed:
// the funnel's record of the seller act (funnel_store.go).
const auditX402Listed = "x402.listed"

// changeX402Listing is x402.submit and x402.withdraw.
func (s *Store) changeX402Listing(ctx context.Context, tx *sql.Tx, c Command, a actor, now int64) (Result, error) {
	if err := requireSigned(a); err != nil {
		return Result{}, err
	}
	e := s.services.engine
	if e == nil || !e.Registry().X402Open() {
		return Result{}, serviceError(services.ErrX402Off)
	}
	method, rawURL, err := services.ParseX402Target(c.Target)
	if err != nil {
		return Result{}, serviceError(err)
	}
	owned, err := s.ownsX402Host(ctx, tx, a.account, method, rawURL)
	if err != nil {
		return Result{}, err
	}
	reg := e.Registry()
	if c.Operation == "x402.withdraw" {
		account := a.account
		return Result{afterCommit: func() (Result, error) {
			data, err := reg.WithdrawX402(context.WithoutCancel(ctx), account, method, rawURL, owned, now)
			if err != nil {
				return Result{}, serviceError(err)
			}
			s.invalidateFind()
			return Result{Data: data}, nil
		}}, nil
	}
	sub := services.X402Submission{Account: a.account, Method: method, URL: rawURL}
	if c.Data != "" {
		var d x402SubmitData
		if services.StrictObject([]byte(c.Data), &d) != nil || d.Schema != 1 {
			return Result{}, problem(400, "x402_listing_data", `x402.submit data is optional: {"schema":1,"summary":"one line","category":"search"}, no other field.`)
		}
		sub.Summary, sub.Category = strings.TrimSpace(d.Summary), d.Category
	}
	if err = services.CheckX402Submission(sub); err != nil {
		return Result{}, serviceError(err)
	}
	// The second proof, for sellers on shared hosting: the challenge pays
	// only wallets the account verified, checked after the probe.
	if sub.Domain = owned; !owned {
		if sub.Wallets, err = accountWallets(ctx, tx, a.account); err != nil {
			return Result{}, err
		}
		if len(sub.Wallets) == 0 {
			return Result{}, x402ListingError("x402_listing_unowned")
		}
	}
	var today int
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM audit WHERE operation='x402.submit' AND target=? AND created_at>=?", a.account, now-now%86400).Scan(&today); err != nil {
		return Result{}, err
	}
	if today >= services.X402SubmitsPerDay {
		return Result{}, rateError(now, "x402_listing_limit", fmt.Sprintf("An account submits at most %d paid APIs per UTC day, refused ones included; it resets at 00:00 UTC.", services.X402SubmitsPerDay))
	}
	if err = s.charge(ctx, tx, a, int64(len(a.canonical))+512, now); err != nil {
		return Result{}, err
	}
	if err = audit(ctx, tx, "x402.submit", a.id, a.account, method+" "+rawURL, now); err != nil {
		return Result{}, err
	}
	actor := a.id
	return Result{afterCommit: func() (Result, error) {
		ctx := context.WithoutCancel(ctx)
		data, err := reg.SubmitX402(ctx, sub, now)
		if err != nil {
			return Result{}, serviceError(err)
		}
		// The seller act, recorded once the listing stands; nothing holds
		// the connection here.
		_, _ = s.db.ExecContext(ctx, "INSERT INTO audit(operation,actor,target,detail,created_at) VALUES(?,?,?,?,?)", auditX402Listed, actor, sub.Account, method+" "+rawURL, now)
		s.invalidateFind()
		return Result{Data: data}, nil
	}}, nil
}

// ownsX402Host reports whether account owns METHOD URL's subject as the
// reviews core decides it: a verified domain link on its host or its
// registrable domain (subjectOwners). An agent offering's page is its
// provider's offering, never a paid API to list.
func (s *Store) ownsX402Host(ctx context.Context, tx *sql.Tx, account, method, rawURL string) (bool, error) {
	sub, err := reviews.Canonical(reviews.TypeX402, method+" "+rawURL, s.subjectOptions())
	if err != nil {
		return false, nil
	}
	owners, err := s.subjectOwners(ctx, tx, sub)
	if err != nil {
		return false, err
	}
	for _, o := range owners {
		if o.Account == account && strings.HasPrefix(o.Link, "domain:") {
			return true, nil
		}
	}
	return false, nil
}

// listedBy is how Find names a submitted listing's submitter: "@HANDLE"
// of the account's current key, or "its verified owner" without one.
// One point read per account, cached in seen for the build.
func (s *Store) listedBy(ctx context.Context, account string, seen map[string]string) (string, error) {
	if v, ok := seen[account]; ok {
		return v, nil
	}
	var handle string
	err := s.db.QueryRowContext(ctx, "SELECT handle FROM identities WHERE account=? AND successor='' AND role='primary' AND handle<>'' ORDER BY created_at DESC LIMIT 1", account).Scan(&handle)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	v := "its verified owner"
	if handle != "" {
		v = "@" + handle
	}
	seen[account] = v
	return v, nil
}

// x402ListingError is the refusal copy of x402.submit and x402.withdraw,
// nil for any other code.
func x402ListingError(code string) error {
	switch code {
	case "x402_listing_unowned":
		return problem(403, "x402_listing_unowned", "List only an API you own, proven one of two ways. Wallet: every payTo of its 402 challenge is a wallet you verified (standing.challenge kind wallet, then identity.link kind wallet, as for offerings). Domain: a verified domain link on the URL's host or registrable domain (the TXT record _swarmmemo.DOMAIN, then identity.link kind domain). Then submit again.")
	case "x402_listing_off":
		return problem(503, "x402_listing_off", "This board's paid API catalogue is off, so it takes no listings now.")
	case "x402_listing_target":
		return problem(400, "x402_listing_target", "target is METHOD URL: GET or POST, then an https URL on port 443 with a public DNS name, such as GET https://api.example.com/search.")
	case "x402_listing_path_template":
		return problem(400, "x402_listing_path_template", "The URL's path has a template such as {id}, which the relay cannot fill: it calls a listing's URL as listed and fills query parameters only. Submit a concrete path (GET https://api.example.com/item/123), or take the value as a query parameter (GET https://api.example.com/item, with id declared in your 402 challenge's input).")
	case "x402_listing_ephemeral_host":
		return problem(400, "x402_listing_ephemeral_host", "Quick-tunnel hostnames change on every restart; list a named tunnel or your own domain.")
	case "x402_listing_summary":
		return problem(400, "x402_listing_summary", fmt.Sprintf("summary is one line of plain text, at most %d bytes.", services.X402SummaryBytes))
	case "x402_listing_category":
		return problem(400, "x402_listing_category", "category is one of the catalogue's categories (the x402 resources read lists them), or leave it out.")
	case "x402_listing_unreachable":
		return problem(422, "x402_listing_unreachable", "The URL did not answer in time (or not over HTTPS with a valid certificate); nothing was listed. Check it is up and public, then submit again.")
	case "x402_listing_no_challenge":
		return problem(422, "x402_listing_no_challenge", "The URL did not answer an unpaid request with a 402 x402 challenge (a PAYMENT-REQUIRED header, or an x402 JSON body with accepts); nothing was listed.")
	case "x402_listing_unsupported":
		return problem(422, "x402_listing_unsupported", "The 402 challenge has no option SwarmMemo pays: scheme exact, USDC by EIP-3009 on the network the x402 resources read names, to a non-zero pay_to. Add one and submit again.")
	case "x402_listing_price":
		return problem(422, "x402_listing_price", "The price is above the catalogue's maximum for one call (caps.open_max_price in the x402 resources read); nothing was listed.")
	case "x402_listing_method":
		return problem(422, "x402_listing_method", "Only GET and POST endpoints are listed.")
	case "x402_listing_url":
		return problem(422, "x402_listing_url", "Only https endpoints on port 443 with a public DNS name are listed.")
	case "x402_listing_denied":
		return problem(403, "x402_listing_denied", "This board's denylist refuses this endpoint (its domain, URL, recipient or category); nothing was listed.")
	case "x402_listing_pinned":
		return problem(409, "x402_listing_pinned", "This endpoint is already in the operator's allowlist: it is listed and callable as it is.")
	case "x402_listing_caps":
		return problem(409, "x402_listing_caps", fmt.Sprintf("The catalogue keeps at most %d unvetted listings per pay_to and %d per registrable domain, and submitted listings fill at most a quarter of it. A submitted listing displaces crawled ones, but here the cap is full of vetted or submitted listings. Withdraw one of yours (x402.withdraw), or ask the operator to vet them.", services.X402PerRecipientMax, services.X402PerDomainMax))
	case "x402_listing_not_found":
		return problem(404, "x402_listing_not_found", "No submitted listing of yours (or on a domain you verified) has that METHOD URL; a crawled listing is not withdrawn this way.")
	}
	return nil
}

// invalidateFind makes the next search rebuild, so it finds a listing just
// changed after commit.
func (s *Store) invalidateFind() {
	if e := s.find.engine.Load(); e != nil {
		e.Invalidate()
	}
}
