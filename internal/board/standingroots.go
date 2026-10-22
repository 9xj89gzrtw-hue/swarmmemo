package board

// Raise your standing (RFC0015 §13, C144): the ways an agent adds priced
// roots to its standing, each through a signed command the page, the API
// and MCP share.
//
//   - standing.challenge issues a single-use, expiring challenge bound to
//     the key that asked: a wallet's Sign-In with Ethereum message, a GitHub
//     statement to publish in a gist, or a proof-of-work nonce. Only the
//     nonce's SHA-256 is stored.
//   - identity.link kind wallet carries the wallet's personal_sign signature
//     of that message and the nonce: checked in the command, verified at
//     once. Its price is Corroborate's resolver total for the address,
//     assessed by the link checker (daily) outside any transaction.
//   - identity.link kind github carries the gist id and the nonce; the link
//     checker reads the gist and the account from GitHub's public API
//     (unauthenticated, rate-limit aware, cached) and verifies it.
//   - standing.work submits a proof-of-work solution; its work accumulates
//     on one pow root per key.
//   - standing.ways reads the list for any public agent: what each way
//     proves, what it adds (the pricing table's range), its state and the one
//     action that adds it.
//
// What is stored is public anyway: an address, a GitHub login and numeric id
// and its public counts, a gist id. The trust run prices each through the
// assessed rows of trust parameter version 5 (internal/trust/roots.go).

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"swarmmemo/internal/proofs"
	"swarmmemo/internal/services"
	"swarmmemo/internal/trust"
)

// Schema 24: standing challenges and assessments.
const standingSchema = `
CREATE TABLE IF NOT EXISTS standing_challenges (
 nonce_sha256 TEXT PRIMARY KEY, agent TEXT NOT NULL, kind TEXT NOT NULL, value TEXT NOT NULL DEFAULT '',
 bits INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, used_at INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS standing_challenges_agent ON standing_challenges(agent,created_at);
CREATE TABLE IF NOT EXISTS standing_assessments (
 agent TEXT NOT NULL, kind TEXT NOT NULL, value TEXT NOT NULL, root TEXT NOT NULL DEFAULT '',
 assessed INTEGER NOT NULL DEFAULT 0, detail TEXT NOT NULL DEFAULT '',
 created_at INTEGER NOT NULL, assessed_at INTEGER NOT NULL DEFAULT 0,
 PRIMARY KEY(agent,kind,value));
`

const (
	// StandingChallengesPerDay bounds wallet and GitHub challenges per key
	// per UTC day; StandingPowPerDay proof-of-work challenges, of which at
	// most StandingPowOpen may be open at once.
	StandingChallengesPerDay = 20
	StandingPowPerDay        = 48
	StandingPowOpen          = 4
	// How long a challenge stays usable, in seconds.
	StandingWalletTTL = 900
	StandingGitHubTTL = 3600
	StandingPowTTL    = 3600
	// Proof-of-work difficulty in leading zero bits of SHA-256.
	StandingPowBitsMin     = 20
	StandingPowBitsMax     = 48
	StandingPowBitsDefault = 24
	StandingPowSolutionMax = 64
	// The fixed prefixes of what a GitHub gist publishes and what a
	// proof-of-work solution hashes.
	GitHubStatementPrefix = "swarmmemo-github:1"
	PowStatementPrefix    = "swarmmemo-pow:1"
	// PowValue is the one pow root's value per key.
	PowValue = "sha256"
	// standingDataBytes is a standing command's data limit: a challenge's
	// fields, or a bond deposit's x402 payment.
	standingDataBytes = 512 + services.TopupPaymentBytes
)

// challengeFlows are the flows standing.challenge issues a challenge for:
// a message to sign, a statement to publish, work to do, a browser flow,
// and the bond's x402 quote. A domain links by its TXT record and an ENS
// name through a wallet link, with no challenge.
var challengeFlows = map[string]bool{proofs.FlowSignature: true, proofs.FlowStatement: true, proofs.FlowWork: true, proofs.FlowOAuth: true,
	proofs.FlowWidget: true, proofs.FlowBond: true}

var (
	githubLoginRE  = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,37}[a-z0-9])?$`)
	gistIDRE       = regexp.MustCompile(`^[0-9a-f]{20,40}$`)
	powSolutionRE  = regexp.MustCompile(`^[A-Za-z0-9]{1,64}$`)
	standingNonceR = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

// normalizeWallet is an EVM address in its EIP-55 form; the zero address is
// nobody's.
func normalizeWallet(raw string) (string, bool) {
	a, ok := services.ParseEVMAddress(raw)
	if !ok || !strings.HasPrefix(raw, "0x") || a == (services.EVMAddress{}) {
		return "", false
	}
	return a.String(), true
}

// walletRoot is a wallet's root: CAIP-10 on Ethereum mainnet, lowercase (an
// externally owned address is the same key on every EVM chain).
func walletRoot(address string) string { return "wallet:eip155:1:" + strings.ToLower(address) }

// normalizeGitHub is a GitHub login, lowercase (GitHub logins ignore case).
func normalizeGitHub(raw string) (string, bool) {
	login := strings.ToLower(raw)
	if !githubLoginRE.MatchString(login) || strings.Contains(login, "--") {
		return "", false
	}
	return login, true
}

// gistID reads a gist id or its URL (https://gist.github.com/LOGIN/ID).
func gistID(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if rest, ok := strings.CutPrefix(raw, "https://gist.github.com/"); ok {
		parts := strings.Split(strings.TrimSuffix(rest, "/"), "/")
		raw = parts[len(parts)-1]
	}
	raw = strings.ToLower(raw)
	return raw, gistIDRE.MatchString(raw)
}

// WalletMessage is the exact EIP-4361 (Sign-In with Ethereum, CAIP-122)
// message a wallet signs to link to fingerprint: no line of it is chosen by
// the signer, and the nonce is the challenge's.
func WalletMessage(serviceID, fingerprint, address, nonce string, issued, expires int64) string {
	return serviceID + " wants you to sign in with your Ethereum account:\n" + address + "\n\n" +
		"Link this address to SwarmMemo agent " + fingerprint + " to raise its standing.\n\n" +
		"URI: https://" + serviceID + "\nVersion: 1\nChain ID: 1\nNonce: " + nonce +
		"\nIssued At: " + time.Unix(issued, 0).UTC().Format(time.RFC3339) +
		"\nExpiration Time: " + time.Unix(expires, 0).UTC().Format(time.RFC3339)
}

// GitHubStatement is the line a gist publishes to link login to fingerprint.
func GitHubStatement(serviceID, fingerprint, login, nonce string) string {
	return GitHubStatementPrefix + ":" + serviceID + ":" + fingerprint + ":" + login + ":" + nonce
}

// PowPrefix is what a proof-of-work solution is appended to before hashing:
// SHA-256(prefix + solution) must start with the challenge's bits of zeros.
func PowPrefix(serviceID, fingerprint, nonce string) string {
	return PowStatementPrefix + ":" + serviceID + ":" + fingerprint + ":" + nonce + ":"
}

// leadingZeroBits counts the leading zero bits of a hash.
func leadingZeroBits(h [32]byte) int64 { return proofs.LeadingZeroBits(h) }

func standingError(code string) error {
	switch code {
	case "invalid_challenge":
		return problem(400, "invalid_challenge", "No such challenge for this key and kind: ask standing.challenge for one, and use it with the key that asked.")
	case "challenge_used":
		return problem(409, "challenge_used", "This challenge was already used: each one works once. Ask standing.challenge for a new one.")
	case "challenge_expired":
		return problem(410, "challenge_expired", "This challenge expired. Ask standing.challenge for a new one.")
	case "challenge_rate":
		return &Error{Status: 429, Code: "challenge_rate", Message: "This key asked for its daily challenges already (" + strconv.Itoa(StandingChallengesPerDay) + " for links and browser sign-ins, " + strconv.Itoa(StandingPowPerDay) + " proof of work, " + strconv.Itoa(StandingPowOpen) + " open at once). Try again after retry_after seconds.", RetryAfter: 3600}
	case "proof_disabled":
		return problem(503, "proof_disabled", "This proof kind is disabled on this server: its operator has not configured the provider's credentials. /capabilities trust.standing.raise lists each kind's status.")
	case "invalid_wallet_signature":
		return problem(400, "invalid_wallet_signature", "The signature is not this address's personal_sign of the challenge's exact message (0x and 130 hex digits). Smart-contract wallets (EIP-1271) are not supported yet.")
	case "invalid_solution":
		return problem(400, "invalid_solution", "SHA-256(prefix + solution) does not start with the challenge's zero bits.")
	}
	return problem(400, "invalid_standing", `Data must be a strict JSON object: standing.challenge {"schema":1,"kind":KIND} with "value" (the address, GitHub login, FID or package) for wallet, github, farcaster, npm and pypi, none for google, x, discord, telegram, reddit and huggingface, optional "bits" (`+strconv.Itoa(StandingPowBitsMin)+` to `+strconv.Itoa(StandingPowBitsMax)+`) for pow, and for bond "usdc" (and "payment"), or "action":"refund", or "action":"settle" with "id" and "tx_hash"; standing.work {"schema":1,"nonce":NONCE,"solution":TEXT} (1 to 64 letters or digits).`)
}

type standingData struct {
	Schema   int    `json:"schema"`
	Kind     string `json:"kind"`
	Value    string `json:"value"`
	Bits     int64  `json:"bits"`
	Nonce    string `json:"nonce"`
	Solution string `json:"solution"`
	// The bond's (proofbond.go).
	Action  string `json:"action"`
	USDC    string `json:"usdc"`
	Payment string `json:"payment"`
	ID      string `json:"id"`
	TxHash  string `json:"tx_hash"`
}

// parseStandingData reads the strict object of a standing command: only the
// named fields, each at most once, none null.
func parseStandingData(raw string, allowed ...string) (standingData, map[string]bool, error) {
	var d standingData
	seen := map[string]bool{}
	if len(raw) > standingDataBytes {
		return d, seen, standingError("")
	}
	dec := json.NewDecoder(strings.NewReader(raw))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return d, seen, standingError("")
	}
	for dec.More() {
		t, err := dec.Token()
		name, ok := t.(string)
		if err != nil || !ok || seen[name] || !(name == "schema" || slices.Contains(allowed, name)) {
			return d, seen, standingError("")
		}
		seen[name] = true
		var v json.RawMessage
		if err = dec.Decode(&v); err != nil || string(v) == "null" {
			return d, seen, standingError("")
		}
		var target any
		switch name {
		case "schema":
			target = &d.Schema
		case "kind":
			target = &d.Kind
		case "value":
			target = &d.Value
		case "bits":
			target = &d.Bits
		case "nonce":
			target = &d.Nonce
		case "solution":
			target = &d.Solution
		case "action":
			target = &d.Action
		case "usdc":
			target = &d.USDC
		case "payment":
			target = &d.Payment
		case "id":
			target = &d.ID
		case "tx_hash":
			target = &d.TxHash
		}
		if err = json.Unmarshal(v, target); err != nil {
			return d, seen, standingError("")
		}
	}
	if t, err := dec.Token(); err != nil || t != json.Delim('}') || dec.More() {
		return d, seen, standingError("")
	}
	if d.Schema != 1 {
		return d, seen, standingError("")
	}
	return d, seen, nil
}

// issueStandingChallenge is standing.challenge.
func (s *Store) issueStandingChallenge(ctx context.Context, tx *sql.Tx, c Command, a actor, now int64) (Result, error) {
	if err := requireSigned(a); err != nil {
		return Result{}, err
	}
	if a.grant != nil {
		return Result{}, linkError("link_delegated")
	}
	d, seen, err := parseStandingData(c.Data, dataSpecs["standing.challenge"].Names(false)...)
	if err != nil {
		return Result{}, err
	}
	prov, ok := s.proofRegistry().Get(d.Kind)
	if !ok || !challengeFlows[prov.Spec().Flow] {
		return Result{}, standingError("")
	}
	spec := prov.Spec()
	if spec.Flow == proofs.FlowBond {
		return s.standingBond(ctx, tx, a, d, seen, now)
	}
	if seen["action"] || seen["usdc"] || seen["payment"] || seen["id"] || seen["tx_hash"] {
		return Result{}, standingError("")
	}
	browser := spec.Flow == proofs.FlowOAuth || spec.Flow == proofs.FlowWidget
	if (spec.Flow == proofs.FlowWork || browser) == seen["value"] || (spec.Flow != proofs.FlowWork && seen["bits"]) {
		return Result{}, standingError("")
	}
	value, ttl, bitsWanted := "", spec.ChallengeTTL, int64(0)
	switch {
	case spec.Flow == proofs.FlowWork:
		bitsWanted = StandingPowBitsDefault
		if seen["bits"] {
			bitsWanted = d.Bits
		}
		if bitsWanted < StandingPowBitsMin || bitsWanted > StandingPowBitsMax {
			return Result{}, standingError("")
		}
		value = PowValue
	case browser:
		if !prov.Enabled() {
			return Result{}, standingError("proof_disabled")
		}
	default:
		v, ok := linkKinds[d.Kind].normalize(d.Value)
		if !ok {
			return Result{}, linkError("invalid_link_value")
		}
		value = v
	}
	// Rate: per key and UTC day, by class; and open proof-of-work challenges.
	day := now - now%86400
	var today, open int64
	pow := d.Kind == "pow"
	if err = tx.QueryRowContext(ctx, `SELECT count(*),coalesce(sum(used_at=0 AND expires_at>?),0) FROM standing_challenges WHERE agent=? AND created_at>=? AND (kind='pow')=?`,
		now, a.id, day, pow).Scan(&today, &open); err != nil {
		return Result{}, err
	}
	if pow && (today >= StandingPowPerDay || open >= StandingPowOpen) || !pow && today >= StandingChallengesPerDay {
		e := standingError("challenge_rate").(*Error)
		e.RetryAfter = int(day + 86400 - now)
		if pow && today < StandingPowPerDay {
			e.RetryAfter = 60
		}
		return Result{}, e
	}
	if err = s.charge(ctx, tx, a, SmallCommandCost, now); err != nil {
		return Result{}, err
	}
	nonce := randomID()
	expires := now + ttl
	if _, err = tx.ExecContext(ctx, "INSERT INTO standing_challenges(nonce_sha256,agent,kind,value,bits,created_at,expires_at) VALUES(?,?,?,?,?,?,?)",
		sha256Hex([]byte(nonce)), a.id, d.Kind, value, bitsWanted, now, expires); err != nil {
		return Result{}, err
	}
	data := map[string]any{"kind": d.Kind, "nonce": nonce, "expires_at": expires, "single_use": true}
	switch d.Kind {
	case "wallet":
		data["value"] = value
		data["message"] = WalletMessage(s.config.ServiceID, a.id, value, nonce, now, expires)
		data["sign_with"] = "personal_sign (EIP-191) of message, by the address's own key"
		data["then"] = `identity.link {"schema":1,"kind":"wallet","value":"` + value + `","proof":SIGNATURE,"nonce":"` + nonce + `"}`
	case "github":
		data["value"] = value
		data["statement"] = GitHubStatement(s.config.ServiceID, a.id, value, nonce)
		data["publish"] = "a public gist by " + value + " whose text contains statement"
		data["then"] = `identity.link {"schema":1,"kind":"github","value":"` + value + `","proof":GIST_ID_OR_URL,"nonce":"` + nonce + `"}`
	case "pow":
		data["bits"] = bitsWanted
		data["prefix"] = PowPrefix(s.config.ServiceID, a.id, nonce)
		data["rule"] = "find solution (1 to 64 letters or digits) with SHA-256(prefix + solution) starting with bits zero bits"
		data["work_units"] = trust.PowUnits(bitsWanted)
		data["then"] = `standing.work {"schema":1,"nonce":"` + nonce + `","solution":SOLUTION}`
	case "farcaster", "npm", "pypi":
		data["value"] = value
		data["statement"] = proofs.Statement(d.Kind, s.config.ServiceID, a.id, value, nonce)
		proof := ""
		switch d.Kind {
		case "farcaster":
			data["publish"] = "cast statement from FID " + value + ", or personal_sign it with the FID's custody address or an address it verified"
			proof = `,"proof":"cast" or SIGNATURE`
		case "npm":
			data["publish"] = `a release of ` + value + ` whose package.json has "swarmmemo": statement (or statement in its description or keywords)`
		case "pypi":
			data["publish"] = "a release of " + value + " whose description (README), summary, keywords or a project URL contains statement"
		}
		data["then"] = `identity.link {"schema":1,"kind":"` + d.Kind + `","value":"` + value + `"` + proof + `,"nonce":"` + nonce + `"}`
	default: // an OAuth provider or the Telegram widget: the browser links it
		data["auth_url"] = s.proofStartURL(d.Kind, nonce)
		data["then"] = "open auth_url in a browser, check the agent it names and approve; the link is verified when " + strings.TrimPrefix(spec.Label, "Link ") + " sends you back (standing.ways shows it)"
	}
	return Result{Data: data}, nil
}

// useStandingChallenge consumes the key's challenge of this kind (and value,
// when one was named): it must exist for this key, be unused and unexpired.
// It returns the challenge's issue time, expiry and bits.
func useStandingChallenge(ctx context.Context, tx *sql.Tx, agent, kind, value, nonce string, now int64) (issued, expires, bitsWanted int64, err error) {
	if !standingNonceR.MatchString(nonce) {
		return 0, 0, 0, standingError("invalid_challenge")
	}
	var used int64
	var gotKind, gotValue string
	err = tx.QueryRowContext(ctx, "SELECT kind,value,bits,created_at,expires_at,used_at FROM standing_challenges WHERE nonce_sha256=? AND agent=?",
		sha256Hex([]byte(nonce)), agent).Scan(&gotKind, &gotValue, &bitsWanted, &issued, &expires, &used)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return 0, 0, 0, standingError("invalid_challenge")
	case err != nil:
		return 0, 0, 0, err
	case gotKind != kind || gotValue != value:
		return 0, 0, 0, standingError("invalid_challenge")
	case used > 0:
		return 0, 0, 0, standingError("challenge_used")
	case now >= expires:
		return 0, 0, 0, standingError("challenge_expired")
	}
	res, err := tx.ExecContext(ctx, "UPDATE standing_challenges SET used_at=? WHERE nonce_sha256=? AND used_at=0", now, sha256Hex([]byte(nonce)))
	if err != nil {
		return 0, 0, 0, err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return 0, 0, 0, standingError("challenge_used")
	}
	return issued, expires, bitsWanted, nil
}

// challengeWallet is identity.link kind wallet's check, in the command: the
// key's unused challenge for this address, and the address's personal_sign
// of its exact message. The link is verified at once; the message is kept
// with it so anyone can check the signature again.
func challengeWallet(ctx context.Context, tx *sql.Tx, s *Store, a actor, d linkData, value string, now int64) (string, string, error) {
	if d.Proof == "" || d.Nonce == "" {
		return "", "", linkError("invalid_link_proof")
	}
	issued, expires, _, err := useStandingChallenge(ctx, tx, a.id, "wallet", value, d.Nonce, now)
	if err != nil {
		return "", "", err
	}
	message := WalletMessage(s.config.ServiceID, a.id, value, d.Nonce, issued, expires)
	wallet, _ := s.proofRegistry().Get("wallet")
	if _, err := wallet.Verify(ctx, proofs.Evidence{Fingerprint: a.id, Value: value, Statement: message, Proof: d.Proof, Now: time.Unix(now, 0)}); err != nil {
		return "", "", standingError("invalid_wallet_signature")
	}
	return "verified", message, nil
}

// challengeGitHub is identity.link kind github's check, in the command: the
// key's unused challenge for this login and a gist id. The link stays claimed
// until the link checker finds the statement in the gist.
func challengeGitHub(ctx context.Context, tx *sql.Tx, s *Store, a actor, d linkData, value string, now int64) (string, string, error) {
	if d.Proof == "" || d.Nonce == "" {
		return "", "", linkError("invalid_link_proof")
	}
	if _, ok := gistID(d.Proof); !ok {
		return "", "", linkError("invalid_link_proof")
	}
	if _, _, _, err := useStandingChallenge(ctx, tx, a.id, "github", value, d.Nonce, now); err != nil {
		return "", "", err
	}
	return "claimed", GitHubStatement(s.config.ServiceID, a.id, value, d.Nonce), nil
}

// submitStandingWork is standing.work: one proof-of-work solution, checked
// with one hash, added to the key's pow root.
// powBitsFor is the smallest challenge size whose one solution, on top of the
// units already assessed, brings proof of work's contribution to cents (C435:
// the route promised "+25¢, cost 0" while a default solution adds ~0¢, since
// the row saturates); 0 when even the largest challenge does not.
func powBitsFor(row trust.ProofPrice, assessed, cents int64) int64 {
	for bits := int64(StandingPowBitsMin); bits <= StandingPowBitsMax; bits++ {
		if trust.AssessedContribution(row, assessed+trust.PowUnits(bits)) >= cents {
			return bits
		}
	}
	return 0
}

func (s *Store) submitStandingWork(ctx context.Context, tx *sql.Tx, c Command, a actor, now int64) (Result, error) {
	if err := requireSigned(a); err != nil {
		return Result{}, err
	}
	if a.grant != nil {
		return Result{}, linkError("link_delegated")
	}
	d, seen, err := parseStandingData(c.Data, dataSpecs["standing.work"].Names(false)...)
	if err != nil {
		return Result{}, err
	}
	if !seen["nonce"] || !seen["solution"] || !powSolutionRE.MatchString(d.Solution) {
		return Result{}, standingError("")
	}
	// Check the hash before spending the challenge, so a wrong solution
	// leaves it usable; the challenge lookup itself is read-only until then.
	if !standingNonceR.MatchString(d.Nonce) {
		return Result{}, standingError("invalid_challenge")
	}
	var wantBits int64
	err = tx.QueryRowContext(ctx, "SELECT bits FROM standing_challenges WHERE nonce_sha256=? AND agent=? AND kind='pow'", sha256Hex([]byte(d.Nonce)), a.id).Scan(&wantBits)
	if errors.Is(err, sql.ErrNoRows) {
		return Result{}, standingError("invalid_challenge")
	}
	if err != nil {
		return Result{}, err
	}
	pow, _ := s.proofRegistry().Get("pow")
	if _, err = pow.Verify(ctx, proofs.Evidence{Fingerprint: a.id, Statement: PowPrefix(s.config.ServiceID, a.id, d.Nonce), Proof: d.Solution, Bits: wantBits, Now: time.Unix(now, 0)}); err != nil {
		return Result{}, standingError("invalid_solution")
	}
	if _, _, _, err = useStandingChallenge(ctx, tx, a.id, "pow", PowValue, d.Nonce, now); err != nil {
		return Result{}, err
	}
	if err = s.charge(ctx, tx, a, SmallCommandCost, now); err != nil {
		return Result{}, err
	}
	units := trust.PowUnits(wantBits)
	var total, solutions int64
	var detail string
	err = tx.QueryRowContext(ctx, "SELECT assessed,detail FROM standing_assessments WHERE agent=? AND kind='pow' AND value=?", a.id, PowValue).Scan(&total, &detail)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return Result{}, err
	}
	var prior struct {
		Solutions int64 `json:"solutions"`
	}
	_ = json.Unmarshal([]byte(detail), &prior)
	solutions = prior.Solutions + 1
	total = min(total+units, 1<<50)
	raw, _ := json.Marshal(map[string]any{"solutions": solutions, "unit": "2^20 expected SHA-256 hashes"})
	if _, err = tx.ExecContext(ctx, `INSERT INTO standing_assessments(agent,kind,value,root,assessed,detail,created_at,assessed_at) VALUES(?,'pow',?,?,?,?,?,?)
 ON CONFLICT(agent,kind,value) DO UPDATE SET assessed=excluded.assessed,detail=excluded.detail,assessed_at=excluded.assessed_at`,
		a.id, PowValue, "pow:"+a.id, total, string(raw), now, now); err != nil {
		return Result{}, err
	}
	if err = audit(ctx, tx, c.Operation, a.id, "pow", "proof of work: "+strconv.FormatInt(units, 10)+" units", now); err != nil {
		return Result{}, err
	}
	data := map[string]any{"bits": wantBits, "work_units": units, "total_work_units": total, "solutions": solutions, "root": "pow:" + a.id}
	if p, err := s.trustParamsAt(ctx, tx, now); err == nil {
		if row, ok := p.Proofs["pow"]; ok {
			counted := trust.AssessedContribution(row, total)
			data["adds_cents"] = counted
			// Say why a solution added little and what reaches the next cent (suifeng2077, 10-17).
			if next := powBitsFor(row, total, counted+1); next > 0 {
				data["note"] = fmt.Sprintf("Proof of work saturates toward its cap: %d units count %s. One solution at bits %d (about 2^%d hashes) reaches the next cent.", total, trust.CentsText(counted), next, next)
			} else {
				data["note"] = fmt.Sprintf("Proof of work saturates toward its cap: %d units count %s; no single challenge adds another cent.", total, trust.CentsText(counted))
			}
		}
	}
	return Result{Data: data}, nil
}

// saveAssessment records an assessment from the link checker, outside any
// transaction.
func (s *Store) saveAssessment(ctx context.Context, agent, kind, value, root string, assessed int64, detail any, now int64) error {
	raw, err := json.Marshal(detail)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO standing_assessments(agent,kind,value,root,assessed,detail,created_at,assessed_at) VALUES(?,?,?,?,?,?,?,?)
 ON CONFLICT(agent,kind,value) DO UPDATE SET root=excluded.root,assessed=excluded.assessed,detail=excluded.detail,assessed_at=excluded.assessed_at`,
		agent, kind, value, root, max(0, assessed), string(raw), now, now)
	return err
}

// checkWalletLink is the wallet link's recheck: its signature was checked
// when it was made and does not lapse, so the check always passes; what it
// renews is the price, Corroborate's resolver total for the address. While
// the resolver is down or not configured the last assessment stands, and the
// run stops counting it after proof_fresh_days.
func (s *Store) checkWalletLink(ctx context.Context, fingerprint, address, _ string) linkOutcome {
	client := s.services.corroborate
	if client == nil {
		return linkPassed
	}
	r, err := client.Resolve(ctx, []string{address}, 0)
	if err != nil {
		return linkPassed
	}
	roots := make([]map[string]any, 0, len(r.Roots))
	for _, root := range r.Roots {
		roots = append(roots, map[string]any{"root": root.Root, "contribution_cents": root.ContributionCents})
	}
	cents := int64(math.Floor(math.Max(0, math.Min(r.TotalCents, 1e12))))
	_ = s.saveAssessment(ctx, fingerprint, "wallet", address, walletRoot(address), cents, map[string]any{
		"source": "corroborate", "total_cents": r.TotalCents, "score": r.Score, "independent_roots": r.IndependentRoots, "roots": roots,
		"registry_revision": r.Registry.Revision, "registry_block": r.Registry.Block, "registry_sha256": r.Registry.SHA256}, s.now().Unix())
	return linkPassed
}

// linkChecker returns the check of a kind: a live kind's lookup, run by the
// rechecker with the link's stored proof.
type linkChecker func(s *Store, ctx context.Context, fingerprint, value, proof string) linkOutcome

// ---- standing.ways ----------------------------------------------------------

// StandingWay is one way to raise an agent's standing, as standing.ways,
// the agent page and /me show it.
type StandingWay struct {
	Kind    string `json:"kind"`
	Label   string `json:"label"`
	Proves  string `json:"proves"`
	Reveals string `json:"reveals"`
	// AddsCents is the range the pricing table allows, in US cents; nil for
	// earned standing, which has no table price.
	AddsCents *StandingRange `json:"adds_cents"`
	// Priced is false when the current trust parameters have no row for
	// this kind yet (versions before 4): it is recorded and counts once they
	// do.
	Priced bool   `json:"priced"`
	State  string `json:"state"`
	Value  string `json:"value,omitempty"`
	Root   string `json:"root,omitempty"`
	// AssessedCents is what the next run reads for this root (capped by the
	// table), when it was assessed; CountedCents what the latest run counted
	// (for a kind the key links several times, all of them together).
	AssessedCents *int64 `json:"assessed_cents,omitempty"`
	CountedCents  *int64 `json:"counted_cents,omitempty"`
	Action        string `json:"action"`
	// Status is a proof kind's: enabled, or disabled-no-credentials while
	// the operator has not configured its provider (OAuth, Telegram).
	Status string `json:"status,omitempty"`
	// Needs are what an agent must already hold to take it (a domain, a
	// wallet, USDC, an account; empty for none) and EffortMinutes about how
	// long it takes: the climb ranks its route by them (C341).
	Needs         []string `json:"needs"`
	EffortMinutes int64    `json:"effort_minutes"`
}

// StandingRange is a price range in US cents.
type StandingRange struct {
	Min int64 `json:"min"`
	Max int64 `json:"max"`
}

// standingWayOther are the two ways that are not proof providers: money
// paid here and earned standing. Every other way is a provider in the
// registry (internal/proofs), which says what it proves, reveals, needs and
// how to add it.
var standingWayOther = map[string]proofs.Spec{
	"money": {Kind: "money", Label: "Pay SwarmMemo", Proves: "Money paid here (credit bought, services paid directly) counts at face value, up to node_cap; it is collateral a penalty destroys.",
		Reveals: "the amount, as the public ledger does.", Needs: []string{proofs.NeedUSDC}, EffortMinutes: 2,
		Action: `credits.topup (USDC) or a paid call: counted in the next trust run`},
	// Its effort is one answered active day's (earnedDayMinutes): time
	// present grows a day at a time.
	"earned": {Kind: "earned", Label: "Earned standing", Proves: "Agents with standing back you over judgement edges: rated accepts, reviews, vouches, up votes, verified witnesses, each passing what it holds above node_cap or " + trust.DefaultParams().PassPercent() + " of what it keeps, whichever is more; and each active day (answered by an independent agent with standing) adds time present.",
		Reveals: "your public activity.", EffortMinutes: earnedDayMinutes,
		Action: `do useful work in public that agents with standing rate (work.accept, review) and answer; their collateral backs you (above node_cap, or ` + trust.DefaultParams().PassPercent() + ` of what they keep), and each answered day adds time present`},
}

// waySpec is a way's spec: its provider's, or money's or earned standing's.
func waySpec(reg *proofs.Registry, kind string) (spec proofs.Spec, provider bool) {
	if prov, ok := reg.Get(kind); ok {
		return prov.Spec(), true
	}
	return standingWayOther[kind], false
}

// StandingWayKinds lists the ways in the order they are shown: every proof
// provider, then money and earned standing.
func StandingWayKinds() []string {
	return append(proofs.Default.Kinds(), "money", "earned")
}

// StandingWayCatalog is every way to raise standing as no one holds it yet,
// priced by the default parameters: /trust#raise lists it read-only, and an
// agent's own list (standing.ways) adds its state.
func StandingWayCatalog() []StandingWay {
	p := trust.DefaultParams()
	var out []StandingWay
	for _, kind := range StandingWayKinds() {
		spec, provider := waySpec(proofs.Default, kind)
		w := StandingWay{Kind: kind, State: "none", Priced: true, Label: spec.Label, Proves: spec.Proves, Reveals: spec.Reveals, Action: spec.Action, EffortMinutes: spec.EffortMinutes}
		if row, ok := p.Proofs[kind]; ok {
			w.AddsCents = &StandingRange{Max: min(row.Forge, row.Rent)}
		} else if provider {
			w.Priced = false
		}
		if kind == "money" {
			w.AddsCents = &StandingRange{Max: p.NodeCapCents}
		}
		out = append(out, w)
	}
	return out
}

// proofRegistry is the store's proof-provider registry.
func (s *Store) proofRegistry() *proofs.Registry {
	if s.config.Proofs != nil {
		return s.config.Proofs
	}
	return proofs.Default
}

// ProofRegistry is the registry, for the HTTP layer's OAuth pages and
// /capabilities.
func (s *Store) ProofRegistry() *proofs.Registry { return s.proofRegistry() }

// StandingWaysTable is docs/PROTOCOL.md's "Raise your standing" table,
// generated from the provider registry and the compiled-in price rows
// (TestGeneratedProtocolSections), so the docs never restate a price.
func StandingWaysTable() string {
	p := trust.DefaultParams()
	var b strings.Builder
	b.WriteString("| Way | `kind` | Root | Adds (cents) | How it is priced | Agent needs | Operator needs |\n|---|---|---|---|---|---|---|\n")
	for _, kind := range proofs.Default.Kinds() {
		prov, _ := proofs.Default.Get(kind)
		spec := prov.Spec()
		row := p.Proofs[kind]
		adds := "up to " + strconv.FormatInt(min(row.Forge, row.Rent), 10)
		if row.Assess == trust.AssessSaturating {
			adds = "under " + strconv.FormatInt(min(row.Forge, row.Rent), 10)
		}
		needs := "nothing"
		switch {
		case len(spec.Env) > 0:
			needs = "`" + strings.Join(spec.Env, "`, `") + "`"
		case kind == "bond":
			needs = "`TOPUP_CONFIG`, `WORK_USDC_RPC_URL`"
		}
		agent := "nothing"
		if len(spec.Needs) > 0 {
			agent = "`" + strings.Join(spec.Needs, "`, `") + "`"
		}
		fmt.Fprintf(&b, "| %s | `%s` | %s | %s | %s | %s | %s |\n", spec.Label, kind, spec.Root, adds, spec.Priced, agent, needs)
	}
	fmt.Fprintf(&b, "\nPrices are trust parameter version %d's `proofs` rows in `/api/params/trust`: each caps its kind's assessment at\nmin(`forge`, `rent`). A kind whose operator has not configured it reads `disabled-no-credentials` in\n`/capabilities` `trust.standing.raise.roots` and answers `503 proof_disabled`. A bond is %s to %s USDC by\ndefault (`PROOF_BOND_MIN_USDC`, `PROOF_BOND_MAX_USDC`) and refundable after %d days (`PROOF_BOND_COOLING_DAYS`).\n",
		trust.DefaultVersion, services.FormatUSDC(BondMinDefault), services.FormatUSDC(BondMaxDefault), BondCoolingDefault)
	return b.String()
}

// RaiseCapabilities is /capabilities trust.standing.raise for this store:
// its registry's statuses and whether bonds are on.
func (s *Store) RaiseCapabilities() map[string]any {
	return StandingCapabilities(s.proofRegistry(), s.BondEnabled())
}

// readStandingWays is standing.ways.
func (s *Store) readStandingWays(ctx context.Context, tx *sql.Tx, c Command, a actor, now int64) (Result, error) {
	if s.config.Features.Trust == TrustOff {
		return Result{}, allowanceError("service_unavailable")
	}
	target := c.Target
	if target == "" && a.signed {
		target = a.id
	}
	if target == "" {
		return Result{}, errNameTheAgent()
	}
	var id, account string
	err := tx.QueryRowContext(ctx, "SELECT i.id,i.account FROM identities i WHERE (i.id=? OR i.handle=?) AND i.successor='' AND ("+publicAccountSQL("i.account")+" OR i.account=?)",
		target, strings.ToLower(target), a.account).Scan(&id, &account)
	if errors.Is(err, sql.ErrNoRows) {
		return Result{}, errAgentNotFound()
	}
	if err != nil {
		return Result{}, err
	}
	ways, view, holds, err := s.standingWays(ctx, tx, id, account, now)
	if err != nil {
		return Result{}, err
	}
	climb, err := s.climbFor(ctx, tx, view, ways, holds, now)
	if err != nil {
		return Result{}, err
	}
	return Result{Data: map[string]any{"agent": id, "ways": ways, "params_version": view.ParamsVersion, "unit": "usd_cent", "standing": view, "climb": climb}}, nil
}

// standingWays builds the list for one key, its standing and what it
// already holds (the climb's climbHolds).
func (s *Store) standingWays(ctx context.Context, q *sql.Tx, id, account string, now int64) ([]StandingWay, *trust.StandingView, climbHolds, error) {
	p, err := s.trustParamsAt(ctx, q, now)
	if err != nil {
		return nil, nil, climbHolds{}, err
	}
	links, err := s.readIdentityLinks(ctx, q, id)
	if err != nil {
		return nil, nil, climbHolds{}, err
	}
	type assessment struct {
		kind, value, root string
		assessed, at      int64
	}
	assessments := map[string]assessment{}
	rows, err := q.QueryContext(ctx, "SELECT kind,value,root,assessed,assessed_at FROM standing_assessments WHERE agent=?", id)
	if err != nil {
		return nil, nil, climbHolds{}, err
	}
	for rows.Next() {
		var x assessment
		if err = rows.Scan(&x.kind, &x.value, &x.root, &x.assessed, &x.at); err != nil {
			rows.Close()
			return nil, nil, climbHolds{}, err
		}
		assessments[x.kind+"\x00"+x.value] = x
	}
	if err = rows.Close(); err != nil {
		return nil, nil, climbHolds{}, err
	}
	view, score, err := trust.CurrentStanding(ctx, q, account, p, now)
	if err != nil {
		return nil, nil, climbHolds{}, err
	}
	counted := map[string]int64{}
	var money int64
	if score != nil {
		for _, item := range score.Parts.World {
			counted[item.Root] += item.Cents
			if item.Kind == "money" {
				money += item.Cents
			}
		}
	}
	fresh := now - p.ProofFreshDays*86400
	reg := s.proofRegistry()
	var ways []StandingWay
	for _, kind := range StandingWayKinds() {
		w := StandingWay{Kind: kind, State: "none", Priced: true}
		spec, provider := waySpec(reg, kind)
		w.Label, w.Proves, w.Reveals, w.Action, w.Needs, w.EffortMinutes = spec.Label, spec.Proves, spec.Reveals, spec.Action, append([]string{}, spec.Needs...), spec.EffortMinutes
		if provider {
			w.Status = reg.Status(kind)
		}
		if row, ok := p.Proofs[kind]; ok {
			w.AddsCents = &StandingRange{Max: min(row.Forge, row.Rent)}
		} else if _, ok := reg.Get(kind); ok {
			w.Priced = false // no row in these parameters yet
		}
		switch kind {
		case "money":
			w.AddsCents = &StandingRange{Max: p.NodeCapCents}
			if money > 0 {
				w.State, w.CountedCents = "verified", &money
			}
		case "earned":
		case "bond":
			if err = s.bondWay(ctx, q, &w, account, counted, now); err != nil {
				return nil, nil, climbHolds{}, err
			}
		case "pow":
			if x, ok := assessments["pow\x00"+PowValue]; ok {
				w.State, w.Value, w.Root = "verified", PowValue, x.root
				if x.at < fresh {
					w.State = "lapsed"
				}
				w.setAmounts(p, x.assessed, counted)
			}
		default:
			for _, l := range links[id] {
				if l.Kind != kind {
					continue
				}
				// The strongest state wins when a key holds several.
				if w.State == "none" || l.State == "verified" && w.State != "verified" {
					w.State, w.Value = l.State, l.Value
					switch kind {
					case "domain":
						w.Root = trust.DomainRoot(l.Value, p.DomainSuffixes)
					case "wallet":
						w.Root = walletRoot(l.Value)
					}
					if x, ok := assessments[kind+"\x00"+l.Value]; ok && x.root != "" {
						w.Root = x.root
						if x.at >= fresh {
							w.setAmounts(p, x.assessed, counted)
						}
					} else if c, ok := counted[w.Root]; ok && w.Root != "" {
						w.CountedCents = &c
					}
				}
			}
			// Several links of one kind (wallets): counted_cents is what the
			// run counted for all of them, so it agrees with the run, where
			// the wallet fallback (C492) and a domain's (C515) count once
			// per root.
			var sum int64
			seen := map[string]bool{}
			for _, l := range links[id] {
				if l.Kind != kind {
					continue
				}
				root := l.Value
				switch kind {
				case "domain":
					root = trust.DomainRoot(l.Value, p.DomainSuffixes)
				case "wallet":
					root = walletRoot(l.Value)
				}
				if x, ok := assessments[kind+"\x00"+l.Value]; ok && x.root != "" {
					root = x.root
				}
				if c, ok := counted[root]; ok && root != "" && !seen[root] {
					seen[root], sum = true, sum+c
				}
			}
			if len(seen) > 1 {
				w.CountedCents = &sum
			}
		}
		ways = append(ways, w)
	}
	var world []trust.WorldItem
	if score != nil {
		world = score.Parts.World
	}
	return ways, view, climbHoldsOf(links[id], ways, world), nil
}

func (w *StandingWay) setAmounts(p trust.Params, assessed int64, counted map[string]int64) {
	if row, ok := p.Proofs[w.Kind]; ok && row.Assess != "" && w.Kind != "domain" {
		v := trust.AssessedContribution(row, assessed)
		w.AssessedCents = &v
	}
	if c, ok := counted[w.Root]; ok {
		w.CountedCents = &c
	}
}

// StandingCapabilities is /capabilities trust.standing.raise: every way,
// each proof kind with its status (enabled, or disabled-no-credentials), its
// flow and its price row (min(forge, rent) caps its assessment).
func StandingCapabilities(reg *proofs.Registry, bondEnabled bool) map[string]any {
	if reg == nil {
		reg = proofs.Default
	}
	p := trust.DefaultParams()
	roots := map[string]any{}
	for _, kind := range StandingWayKinds() {
		spec, provider := waySpec(reg, kind)
		entry := map[string]any{"label": spec.Label, "proves": spec.Proves, "reveals": spec.Reveals, "action": spec.Action,
			"needs": append([]string{}, spec.Needs...), "effort_minutes": spec.EffortMinutes}
		if provider {
			entry["flow"], entry["root"], entry["priced"], entry["status"] = spec.Flow, strings.ReplaceAll(spec.Root, "`", ""), spec.Priced, reg.Status(kind)
			if len(spec.Env) > 0 {
				entry["credentials"] = spec.Env
			}
		}
		if row, ok := p.Proofs[kind]; ok {
			entry["cap_cents"] = min(row.Forge, row.Rent)
			entry["forge"], entry["rent"] = row.Forge, row.Rent
			if row.Assess != "" {
				entry["assess"] = row.Assess
			}
		}
		if kind == "money" {
			entry["cap_cents"] = p.NodeCapCents
		}
		roots[kind] = entry
	}
	roots["pow"].(map[string]any)["bits"] = map[string]int{"minimum": StandingPowBitsMin, "maximum": StandingPowBitsMax, "default": StandingPowBitsDefault}
	roots["bond"].(map[string]any)["usdc"] = map[string]any{"minimum": services.FormatUSDC(BondMinDefault), "maximum": services.FormatUSDC(BondMaxDefault), "cooling_days": BondCoolingDefault}
	if !bondEnabled {
		// The bond needs the x402 rails (TOPUP_CONFIG) and a chain reader
		// for refunds (WORK_USDC_RPC_URL).
		roots["bond"].(map[string]any)["status"] = "disabled-no-credentials"
		roots["bond"].(map[string]any)["credentials"] = []string{"TOPUP_CONFIG", "WORK_USDC_RPC_URL"}
	}
	return map[string]any{
		"read":      "standing.ways, GET /api/agent/AGENT/standing",
		"challenge": `standing.challenge {"schema":1,"kind":KIND}: single use, bound to the key that asked; wallet expires in ` + strconv.Itoa(StandingWalletTTL/60) + ` minutes, an OAuth or Telegram state in ` + strconv.Itoa(proofs.OAuthTTL/60) + `, npm and PyPI in a day, the rest in an hour; an OAuth kind answers auth_url to open in a browser`,
		"link":      "identity.link with the challenge's nonce (wallet, github, farcaster, npm, pypi), or kind ens after a wallet link; OAuth and Telegram links are made by the browser flow",
		"oauth":     map[string]any{"start": "/proofs/oauth/KIND/start?state=NONCE", "redirect_uri": "PUBLIC_URL/proofs/oauth/KIND/callback", "pkce": "S256", "scopes": "identity only", "token_kept": false},
		"limits":    map[string]int{"challenges_per_day": StandingChallengesPerDay, "pow_challenges_per_day": StandingPowPerDay, "pow_open": StandingPowOpen},
		"roots":     roots,
		"prices":    "/api/params/trust proofs.KIND",
		"docs":      "/protocol.md#raise-your-standing",
	}
}
