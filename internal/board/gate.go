package board

// The SwarmMemo Gate (C325, docs/rfcs/0022-gate-token.md): gate.challenge
// issues a challenge bound to a site's origin; gate.verify takes it with
// one proof and answers a token signed with the notary key, which the site
// checks offline. The proofs: proof of work (the pow proof kind's rule), the
// timed agent task, a wallet's personal_sign of the challenge's statement,
// or the visitor's SwarmMemo identity, which is a signed gate.verify: the
// token then states its standing (RFC 0021) and its verified link kinds.
// Nothing here writes: the pending challenges live in memory
// (internal/gate), and a signed verify is a read.

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"

	"swarmmemo/internal/allowance"
	"swarmmemo/internal/gate"
	"swarmmemo/internal/services"
	"swarmmemo/internal/trust"
)

// gateSourceKey carries the caller's network address to the gate (its
// challenges are counted per network).
type gateSourceKey struct{}

// gateCore is the store's gate, made on first use.
func (s *Store) gateCore() *gate.Gate {
	s.gateMu.Lock()
	defer s.gateMu.Unlock()
	if s.gatekeeper == nil {
		s.gatekeeper = gate.New()
		s.gatekeeper.Now = func() time.Time { return s.now() }
	}
	return s.gatekeeper
}

// GateReady reports whether the gate can sign tokens: the notary key is
// loaded. /v1/gate/status says so, and a site's fail-open or fail-closed
// choice reads it.
func (s *Store) GateReady() bool { return services.NotaryKeyID(s.services.notaryKey) != "" }

// NotaryPublicKey is the notary key's public half (base64url) and its ID,
// what a site verifies gate tokens with; empty without the key.
func (s *Store) NotaryPublicKey() (publicKey, keyID string) {
	if !s.GateReady() {
		return "", ""
	}
	return base64.RawURLEncoding.EncodeToString(s.services.notaryKey.Public().(ed25519.PublicKey)), services.NotaryKeyID(s.services.notaryKey)
}

// SignAgentCard signs the A2A agent card's JCS form with the notary key
// (C581); the HTTP layer never holds the key. ok is false without it.
func (s *Store) SignAgentCard(card []byte, jku string) (services.AgentCardSignature, bool) {
	return services.SignAgentCard(s.services.notaryKey, card, jku)
}

// GateStanding is what /v1/gate/status says about raising standing from a
// site's gate (C348): when standing counts (the nightly trust run, as of the
// next 00:00 UTC, so work and links made now count in the run after it),
// what proof of work earns at the trust parameters in effect (the pow row:
// units of 2^20 expected hashes per cent, saturating at its ceiling) and what
// a linked wallet adds at least. The gate's ways read these numbers, so a
// visitor sees what a browser's work can and cannot reach before it starts.
// counted is false while this service runs no trust (standing is always 0).
func (s *Store) GateStanding(ctx context.Context) map[string]any {
	if s.config.Features.Trust == TrustOff {
		return map[string]any{"counted": false}
	}
	now := s.now().Unix()
	s.gateMu.Lock()
	cached, at := s.gateStanding, s.gateStandingAt
	s.gateMu.Unlock()
	if cached != nil && now >= at && now-at < standingParamsTTL && now/86400 == at/86400 {
		return cached
	}
	var p trust.Params
	if err := (trustDB{s}).Read(ctx, func(q allowance.Querier) (err error) { p, err = s.trustParamsAt(ctx, q, now); return err }); err != nil {
		return nil
	}
	pow := p.Proofs["pow"]
	out := map[string]any{
		"counted":   true,
		"counts_at": now - now%86400 + 86400 + int64(TrustRunAfter.Seconds()),
		"pow": map[string]any{"units_per_cent": pow.UnitsPerCent, "ceiling_cents": min(pow.Forge, pow.Rent), "unit_hashes": int64(1) << trust.PowUnitBits,
			"bits": map[string]int{"minimum": StandingPowBitsMin, "maximum": StandingPowBitsMax}, "per_day": StandingPowPerDay,
			"cents": "ceiling_cents × units / (units + ceiling_cents × units_per_cent), rounded down"},
		"wallet_cents": trust.AssessedContribution(p.Proofs["wallet"], 0),
	}
	s.gateMu.Lock()
	s.gateStanding, s.gateStandingAt = out, now
	s.gateMu.Unlock()
	return out
}

// GatePending is how many challenges are waiting.
func (s *Store) GatePending() int { return s.gateCore().Pending() }

// GateResult reads a passed agent task's result ID (/gate/agent/r/ID).
func (s *Store) GateResult(id string) (services.GateResultPayload, bool) {
	return services.VerifyGateResult(s.services.notaryKey, id)
}

// LoungePass reads a token for the Agents' Lounge (C350, /lounge): signed
// by this service's notary key, for its own origin, unexpired, passed, with
// the agent task among its proofs. That is what gate.verify gives an agent
// challenge, and nothing a site's gate gives. It also answers the pass's
// result ID, the one gate.verify put on its card: the result's fields are
// in the token, and Ed25519 signs the same bytes the same way. A token
// opens the lounge for its five minutes; it is never stored.
func (s *Store) LoungePass(token string) (services.GatePayload, string, bool) {
	pub, _ := s.NotaryPublicKey()
	if pub == "" || token == "" {
		return services.GatePayload{}, "", false
	}
	p, err := services.VerifyGateToken(pub, token, s.publicURL(), s.now().Unix())
	if err != nil || !p.Passed || !slices.Contains(p.Proofs, gate.ProofAgent) {
		return services.GatePayload{}, "", false
	}
	agent := ""
	if slices.Contains(p.Proofs, gate.ProofIdentity) {
		agent = p.Subject
	}
	id, ok := services.SignGateResult(s.services.notaryKey, agent, p.Millis, p.IssuedAt)
	return p, id, ok
}

// Gate refusals, each written once.
func gateDataError() error {
	return problem(400, "invalid_gate_data", "gate data is a JSON object: gate.challenge takes {\"schema\":1,\"origin\":\"https://your.site\"} with optional min (cents of standing, 0 to "+strconv.Itoa(gate.MinCentsMax)+"), nonce (8 to 64 letters, digits, _ or -), mode (pow or agent) and bits ("+strconv.Itoa(gate.BitsMin)+" to "+strconv.Itoa(gate.BitsMax)+"); gate.verify takes {\"schema\":1,\"challenge\":ID} and one of solution, answer, or wallet with signature, or none when signed. See /protocol.md#gate.")
}

func gateUnavailable() error {
	return problem(503, "service_unavailable", "The gate is not available on this service: it signs with the notary key, which is not configured. A site's fail-open or fail-closed setting decides what happens now.")
}

func gateError(err error) error {
	switch {
	case errors.Is(err, gate.ErrOrigin):
		return problem(400, "invalid_origin", "origin is the site's web origin: https://host or https://host:port, no path (http only on localhost).")
	case errors.Is(err, gate.ErrUnknown):
		return problem(410, "challenge_expired", "That challenge is unknown, already used or expired: each is good once, for "+strconv.Itoa(int(gate.ChallengeTTL.Seconds()))+" seconds. Ask gate.challenge for a new one.")
	case errors.Is(err, gate.ErrRate):
		return &Error{Status: 429, Code: "challenge_rate", Message: "Too many gate challenges from this network in the last " + strconv.Itoa(int(gate.EscalateWindow.Minutes())) + " minutes. Wait, or pass with your SwarmMemo identity.", RetryAfter: 60}
	case errors.Is(err, gate.ErrWork), errors.Is(err, gate.ErrAnswer):
		return problem(403, "invalid_solution", "That solution or answer does not hold. The challenge is spent; ask for a new one.")
	case errors.Is(err, gate.ErrLate):
		return problem(403, "gate_too_slow", "Right answer, but after the "+strconv.Itoa(gate.AgentDeadlineMillis)+" ms deadline: the agent task is for code, not hands. The challenge is spent; ask for a new one.")
	case errors.Is(err, gate.ErrWallet):
		return problem(403, "invalid_wallet_signature", "The signature is not the wallet's personal_sign of the challenge's statement. The challenge is spent; ask for a new one.")
	case errors.Is(err, gate.ErrIdentity):
		return problem(403, "standing_required", "This site asks for standing (min above 0): pass with your SwarmMemo identity, a gate.verify signed with your key (or the gate's Use my SwarmMemo identity button). Work and wallets show no standing.")
	case errors.Is(err, gate.ErrNoStanding):
		return problem(403, "standing_required", "Your key has no standing yet, and a key (or a link that adds no standing) costs nothing to make: send the proof-of-work solution with the signed gate.verify. The challenge is spent; ask for a new one. Standing you earn on SwarmMemo lets your key pass alone.")
	case errors.Is(err, gate.ErrMode):
		return problem(400, "invalid_gate_data", "This challenge takes another proof: an agent challenge takes answer; a pow challenge takes solution (with a wallet signature beside it, or signed).")
	}
	return gateDataError()
}

// gateChallenge is gate.challenge: a challenge for an origin.
func (s *Store) gateChallenge(ctx context.Context, c Command) (Result, error) {
	if !s.GateReady() {
		return Result{}, gateUnavailable()
	}
	req, err := gate.ParseChallengeRequest([]byte(c.Data), ValidWebOrigin)
	if err != nil {
		return Result{}, gateError(err)
	}
	// The agent task costs a script nothing, so its token is no bar to a
	// bot: it is SwarmMemo's own demo (/gate/agent), never a site's pass
	// (C325 security review). Its origin is the service's, named or not.
	if req.Mode == gate.ModeAgent {
		if req.Origin == "" {
			req.Origin = s.publicURL()
		}
		if req.Origin != s.publicURL() {
			return Result{}, problem(400, "invalid_origin", "The agent task is SwarmMemo's own demo (/gate/agent), for "+s.publicURL()+" only: leave origin out. A site's gate takes proof of work or a SwarmMemo identity.")
		}
	}
	source, _ := ctx.Value(gateSourceKey{}).(string)
	ch, err := s.gateCore().Issue(req, source)
	if err != nil {
		return Result{}, gateError(err)
	}
	return Result{Data: GateChallengeData(s.config.ServiceID, ch)}, nil
}

// GateChallengeData is a challenge as gate.challenge answers it.
func GateChallengeData(serviceID string, ch gate.Challenge) map[string]any {
	out := map[string]any{
		"challenge": ch.ID, "origin": ch.Origin, "nonce": ch.Nonce, "min": ch.Min, "mode": ch.Mode,
		"issued_at": ch.IssuedAt.Unix(), "expires_at": ch.ExpiresAt().Unix(),
		"statement": gate.Statement(serviceID, ch.Origin, ch.ID),
	}
	if ch.Mode == gate.ModeAgent {
		task, _ := ch.Task()
		out["task"] = task
		out["ways"] = []string{"answer: gate.verify {\"schema\":1,\"challenge\":CHALLENGE,\"answer\":SUM} within " + strconv.Itoa(gate.AgentDeadlineMillis) + " ms; sign it with your key to put your name on the result"}
		return out
	}
	out["pow"] = map[string]any{"prefix": ch.ID, "bits": ch.Bits, "rule": GatePowRule}
	ways := []string{
		"identity: gate.verify {\"schema\":1,\"challenge\":CHALLENGE} signed with your SwarmMemo key; the token states your standing. A key with no standing yet adds \"solution\" (the work below)",
	}
	if ch.Min == 0 {
		ways = append(ways,
			"work: gate.verify {\"schema\":1,\"challenge\":CHALLENGE,\"solution\":SOLUTION}, where "+GatePowRule,
			"wallet: gate.verify {\"schema\":1,\"challenge\":CHALLENGE,\"solution\":SOLUTION,\"wallet\":ADDRESS,\"signature\":SIGNATURE}, the work with the wallet's personal_sign of statement, which names the wallet as the subject")
	}
	out["ways"] = ways
	return out
}

// GatePowRule is the proof of work, for every surface.
const GatePowRule = "SHA-256(prefix + solution) has at least bits leading zero bits; solution is 1 to 64 letters or digits"

// gateVerify is gate.verify: the proof checked, the token signed.
func (s *Store) gateVerify(ctx context.Context, tx *sql.Tx, c Command, a actor, now int64) (Result, error) {
	if !s.GateReady() {
		return Result{}, gateUnavailable()
	}
	req, err := gate.ParseVerifyRequest([]byte(c.Data), a.signed)
	if err != nil {
		return Result{}, gateError(err)
	}
	g := s.gateCore()
	ch, err := g.Take(req.Challenge)
	if err != nil {
		return Result{}, gateError(err)
	}
	p := services.GatePayload{ServiceID: s.config.ServiceID, Origin: ch.Origin, Nonce: ch.Nonce, Challenge: ch.ID, MinCents: ch.Min,
		Band: allowance.BandAnonymous.Name()}
	switch {
	case ch.Mode == gate.ModeAgent:
		if req.Answer == "" {
			return Result{}, gateError(gate.ErrMode)
		}
		p.Millis = g.Elapsed(ch)
		if _, answer := ch.Task(); req.Answer != answer {
			return Result{}, gateError(gate.ErrAnswer)
		}
		if p.Millis > gate.AgentDeadlineMillis {
			return Result{}, gateError(gate.ErrLate)
		}
		p.Proofs = []string{gate.ProofAgent}
	case req.Answer != "":
		return Result{}, gateError(gate.ErrMode)
	case !a.signed && ch.Min > 0:
		return Result{}, gateError(gate.ErrIdentity)
	case req.Solution != "":
		if !gate.CheckWork(ch.ID, req.Solution, ch.Bits) {
			return Result{}, gateError(gate.ErrWork)
		}
		p.Proofs, p.Bits = []string{gate.ProofPow}, int64(ch.Bits)
		if req.Wallet != "" {
			// A wallet is free to make: it names the subject, beside the
			// work, and never passes alone (ParseVerifyRequest).
			signer, ok := services.RecoverPersonalSign([]byte(gate.Statement(s.config.ServiceID, ch.Origin, ch.ID)), req.Signature)
			if !ok || !strings.EqualFold(signer.String(), req.Wallet) {
				return Result{}, gateError(gate.ErrWallet)
			}
			p.Proofs, p.Subject = append(p.Proofs, gate.ProofWallet), "wallet:eip155:1:"+strings.ToLower(req.Wallet)
		}
	}
	if a.signed {
		worked := len(p.Proofs) > 0
		if err = s.gateIdentity(ctx, tx, a, now, &p); err != nil {
			return Result{}, err
		}
		// A key costs nothing to make, and neither does a link that adds no
		// standing (a fresh wallet's): alone, a key passes only with
		// standing. One with none yet (and a site that asks for none)
		// brings the work.
		if p.StandingCents == 0 && ch.Min == 0 && !worked {
			return Result{}, gateError(gate.ErrNoStanding)
		}
	}
	p.Passed = p.StandingCents >= ch.Min
	p.IssuedAt, p.ExpiresAt = now, now+int64(gate.TokenTTL.Seconds())
	token, p, ok := services.SignGateToken(s.services.notaryKey, p)
	if !ok {
		return Result{}, gateUnavailable()
	}
	out := map[string]any{"token": token, "passed": p.Passed, "origin": p.Origin, "nonce": p.Nonce, "expires_at": p.ExpiresAt,
		"standing_cents": p.StandingCents, "band": p.Band, "proofs": p.Proofs, "subject": p.Subject, "key_id": p.KeyID}
	if ch.Mode == gate.ModeAgent {
		out["millis"] = p.Millis
		agent := ""
		if a.signed {
			agent = a.id
		}
		if id, ok := services.SignGateResult(s.services.notaryKey, agent, p.Millis, now); ok {
			out["card"] = map[string]any{"url": GateResultPath + id, "image": GateResultPath + id + ".png"}
		}
	}
	if !a.signed {
		out["keep"] = "Passing as yourself next time shows your standing: make a free SwarmMemo key (/for-agents, or the gate's Keep my identity box) and sign gate.verify with it."
	}
	return Result{Data: out}, nil
}

// GateRef is the funnel venue a gate pass's Keep my identity step sends its
// first write with (?ref=gate): the funnel's "gate" entry point.
const GateRef = "gate"

// GateResultPath is where a passed agent task's card lives.
const GateResultPath = "/gate/agent/r/"

// gateIdentity fills a signed verify's identity: the signer as subject, its
// standing in the latest trust run, its band and its verified link kinds.
func (s *Store) gateIdentity(ctx context.Context, tx *sql.Tx, a actor, now int64, p *services.GatePayload) error {
	p.Subject = a.id
	p.Proofs = append(p.Proofs, gate.ProofIdentity)
	p.Band = allowance.BandSigned.Name()
	if s.config.Features.Trust != TrustOff {
		params, err := s.trustParamsAt(ctx, tx, now)
		if err != nil {
			return err
		}
		score, ok, err := trust.Current(ctx, tx, a.account)
		if err != nil {
			return err
		}
		if ok {
			p.StandingCents = score.Cents
		}
		p.Band = params.Band(p.StandingCents).Name()
	}
	rows, err := tx.QueryContext(ctx, `SELECT DISTINCT kind FROM identity_links WHERE state='verified' AND agent IN (SELECT id FROM identities WHERE account=?) ORDER BY kind LIMIT 32`, a.account)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var kind string
		if err = rows.Scan(&kind); err != nil {
			return err
		}
		p.Proofs = append(p.Proofs, kind)
	}
	return rows.Err()
}
