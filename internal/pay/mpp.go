package pay

// mppWire is MPP, the "Payment" HTTP authentication scheme
// (draft-httpauth-payment-01), with the evm method's charge intent and
// credential type "authorization" (draft-evm-charge-00): the same EIP-3009
// transferWithAuthorization x402 exact signs, with
// nonce = keccak256(challenge.id ‖ realm), so it settles on the same rail.
//
//	402  WWW-Authenticate: Payment id, realm, method="evm", intent="charge",
//	     request=b64url(JCS{amount, currency, methodDetails, recipient}),
//	     expires, [digest], [opaque=b64url(JCS{"q": quote})], [header]
//	     Cache-Control: no-store; body application/problem+json
//	retry Authorization: Payment b64url({challenge: echo, source?, payload})
//	     (Payment-Authorization when the challenge said header=)
//	2xx  Payment-Receipt: b64url(JCS{challengeId, chainId, method, reference,
//	     status, timestamp}); Cache-Control: private
//
// The challenge id is the spec's recommended HMAC-SHA256 binding over every
// other parameter, keyed by HKDF(the caller's quote key,
// "swarmmemo-mpp-challenge/1"). It is stateless: Bound rebuilds the
// challenge from the Ask the caller reconstructs from its own quote (which
// the payer echoes in opaque), and compares.

import (
	"bytes"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"swarmmemo/internal/jcs"
)

// MPP bounds and names.
const (
	// MPPCredentialBytes bounds a credential (the base64url after
	// "Payment "): the spec asks servers to take at least 4 KB.
	MPPCredentialBytes = 8 << 10
	// MPPChallengeBytes bounds one challenge we write or read: the spec
	// asks servers to keep challenges under 8 KB.
	MPPChallengeBytes = 8 << 10
	// MPPKeyInfo is the HKDF info that derives the challenge-id key from
	// the caller's quote key.
	MPPKeyInfo = "swarmmemo-mpp-challenge/1"
	// ProblemContentType is the media type of an MPP error body.
	ProblemContentType = "application/problem+json"
	// ProblemBase is the spec's base URI for problem types.
	ProblemBase = "https://paymentauth.org/problems/"
	// Permit2Address is Permit2's canonical deployment, which the evm
	// method's methodDetails names (we accept only "authorization").
	Permit2Address = "0x000000000022D473030F116dDEE9F6B43aC78BA3"

	mppScheme                  = "Payment"
	mppMethod                  = "evm"
	mppIntent                  = "charge"
	mppCredentialType          = "authorization"
	headerWWWAuthenticate      = "Www-Authenticate"
	headerAuthorization        = "Authorization"
	headerPaymentAuthorization = "Payment-Authorization"
	headerPaymentReceipt       = "Payment-Receipt"
	// usdcDecimals: every rail amount is micro-USDC (services' top-up
	// config requires a 6-decimal USD token).
	usdcDecimals = 6
	// mppDescriptionBytes bounds the display-only description we write.
	mppDescriptionBytes = 512
)

type mppWire struct {
	rail    Rail
	chainID int64
	realm   string
	key     []byte
}

var realmRE = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,252})(:[0-9]{1,5})?$`)

// NewMPP is the MPP wire on rail: realm is this server's host (the
// protection space), secret the caller's quote key, from which the
// challenge-id key is derived (HKDF-SHA256, info MPPKeyInfo), so MPP needs
// no new secret.
func NewMPP(rail Rail, realm string, secret []byte) (Wire, error) {
	chainID, ok := rail.ChainID()
	if !ok || rail.Asset == (EVMAddress{}) {
		return nil, errors.New("pay: MPP needs an eip155 rail with an asset")
	}
	if !realmRE.MatchString(realm) {
		return nil, errors.New("pay: MPP realm must be a host name")
	}
	if len(secret) < 16 {
		return nil, errors.New("pay: MPP secret too short")
	}
	key, err := hkdf.Key(sha256.New, secret, nil, MPPKeyInfo, 32)
	if err != nil {
		return nil, err
	}
	return mppWire{rail: rail, chainID: chainID, realm: realm, key: key}, nil
}

func (w mppWire) Name() string { return WireMPP }

// mppParams is one challenge's parameters as they appear on the wire; an
// empty optional parameter is absent.
type mppParams struct {
	ID, Realm, Method, Intent, Request string
	Expires, Digest, Opaque, Header    string
	Description                        string // display only, never bound
}

// MPPChallengeID is the spec's recommended HMAC-SHA256 binding:
// base64url(HMAC(key, realm|method|intent|request|expires|digest[|header]|opaque)),
// the header slot only when header is present.
func MPPChallengeID(key []byte, realm, method, intent, request, expires, digest, header, opaque string) string {
	slots := []string{realm, method, intent, request, expires, digest}
	if header != "" {
		slots = append(slots, header)
	}
	slots = append(slots, opaque)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(strings.Join(slots, "|")))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// ChallengeNonce is the EIP-3009 nonce an evm "authorization" credential
// must carry: keccak256(abi.encodePacked(challenge.id, challenge.realm)),
// which is the two strings' bytes, concatenated.
func ChallengeNonce(id, realm string) [32]byte {
	return Keccak256([]byte(id), []byte(realm))
}

func challengeNonceHex(id, realm string) string {
	n := ChallengeNonce(id, realm)
	return "0x" + hex.EncodeToString(n[:])
}

// ContentDigest is the RFC 9530 sha-256 digest of body, as the digest
// parameter carries it.
func ContentDigest(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha-256=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"
}

// mppRequest is the charge request for a, JCS and base64url.
func (w mppWire) mppRequest(a Ask) (string, error) {
	raw, err := jcs.Encode(map[string]any{
		"amount":    strconv.FormatInt(a.Amount, 10),
		"currency":  w.rail.Asset.String(),
		"recipient": a.PayTo.String(),
		"methodDetails": map[string]any{
			"chainId":         w.chainID,
			"credentialTypes": []string{mppCredentialType},
			"decimals":        usdcDecimals,
			"permit2Address":  Permit2Address,
		},
	})
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// build is the challenge for a: every parameter, and its id.
func (w mppWire) build(a Ask) (mppParams, error) {
	if a.PayTo == (EVMAddress{}) || a.Amount <= 0 || a.Expires <= 0 || a.Expires > 1<<40 || (a.Quote != "" && !quoteRE.MatchString(a.Quote)) {
		return mppParams{}, errors.New("pay: MPP ask is incomplete")
	}
	p := mppParams{Realm: w.realm, Method: mppMethod, Intent: mppIntent,
		Expires: time.Unix(a.Expires, 0).UTC().Format(time.RFC3339), Description: displayText(a.Description)}
	var err error
	if p.Request, err = w.mppRequest(a); err != nil {
		return mppParams{}, err
	}
	if a.Body != nil {
		p.Digest = ContentDigest(a.Body)
	}
	if a.Quote != "" {
		raw, err := jcs.Encode(map[string]string{"q": a.Quote})
		if err != nil {
			return mppParams{}, err
		}
		p.Opaque = base64.RawURLEncoding.EncodeToString(raw)
	}
	if a.PaymentAuthorization {
		p.Header = headerPaymentAuthorization
	}
	p.ID = MPPChallengeID(w.key, p.Realm, p.Method, p.Intent, p.Request, p.Expires, p.Digest, p.Header, p.Opaque)
	return p, nil
}

// displayText is s fit for a quoted-string: no control characters, valid
// UTF-8, bounded.
func displayText(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f || r == utf8.RuneError || (r >= 0x80 && r < 0xa0) {
			continue
		}
		if b.Len()+utf8.RuneLen(r) > mppDescriptionBytes {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}

// quoted is s as an RFC 9110 quoted-string.
func quoted(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

// format is p as a WWW-Authenticate field value.
func (p mppParams) format() string {
	var b strings.Builder
	b.WriteString(mppScheme + " id=" + quoted(p.ID) + ", realm=" + quoted(p.Realm) + ", method=" + quoted(p.Method) +
		", intent=" + quoted(p.Intent) + ", request=" + quoted(p.Request))
	for _, kv := range [][2]string{{"expires", p.Expires}, {"digest", p.Digest}, {"opaque", p.Opaque}, {"header", p.Header}, {"description", p.Description}} {
		if kv[1] != "" {
			b.WriteString(", " + kv[0] + "=" + quoted(kv[1]))
		}
	}
	return b.String()
}

// Challenge adds one WWW-Authenticate: Payment challenge for a to h, sets
// Cache-Control: no-store, and returns the RFC 9457 payment-required body.
func (w mppWire) Challenge(a Ask, h http.Header) (map[string]any, error) {
	p, err := w.build(a)
	if err != nil {
		return nil, err
	}
	v := p.format()
	if len(v) > MPPChallengeBytes {
		return nil, errors.New("pay: MPP challenge too large")
	}
	h.Add(headerWWWAuthenticate, v)
	h.Set("Cache-Control", "no-store")
	body := w.Problem("payment_required", "Payment required: pay "+strconv.FormatInt(a.Amount, 10)+" atomic units of "+w.rail.Asset.String()+" on chain "+strconv.FormatInt(w.chainID, 10)+".").Body
	body["challengeId"] = p.ID
	return body, nil
}

// paymentToken is the credential in an Authorization-style value whose
// scheme is Payment (case-insensitive), or false.
func paymentToken(v string) (string, bool) {
	v = strings.TrimLeft(v, " \t")
	scheme, rest, ok := strings.Cut(v, " ")
	if !ok || !strings.EqualFold(scheme, mppScheme) {
		return "", false
	}
	return strings.Trim(rest, " \t"), true
}

// Credential is the one Payment credential in Authorization or
// Payment-Authorization. Authorization with another scheme (Bearer) is not
// a payment and is left alone; Payment-Authorization with another scheme
// is malformed.
func (w mppWire) Credential(h http.Header) (string, string, error) {
	var values, fields []string
	for _, v := range h.Values(headerAuthorization) {
		if tok, ok := paymentToken(v); ok {
			values, fields = append(values, tok), append(fields, headerAuthorization)
		}
	}
	for _, v := range h.Values(headerPaymentAuthorization) {
		tok, ok := paymentToken(v)
		if !ok {
			return "", "", refusal(CodeInvalid)
		}
		values, fields = append(values, tok), append(fields, headerPaymentAuthorization)
	}
	switch {
	case len(values) == 0:
		return "", "", ErrNoCredential
	case len(values) > 1:
		return "", "", ErrManyCredentials
	case len(values[0]) > MPPCredentialBytes:
		return "", "", refusal(CodeInvalid)
	}
	return values[0], fields[0], nil
}

// mppEcho is the challenge a credential echoes; nil optional fields were
// absent.
type mppEcho struct {
	ID, Realm, Method, Intent, Request string
	Expires, Digest, Opaque, Header    *string
}

type mppCredentialWire struct {
	Challenge json.RawMessage `json:"challenge"`
	Source    *string         `json:"source"`
	Payload   json.RawMessage `json:"payload"`
}

type mppEchoWire struct {
	ID          *string `json:"id"`
	Realm       *string `json:"realm"`
	Method      *string `json:"method"`
	Intent      *string `json:"intent"`
	Request     *string `json:"request"`
	Description *string `json:"description"`
	Opaque      *string `json:"opaque"`
	Digest      *string `json:"digest"`
	Expires     *string `json:"expires"`
	Header      *string `json:"header"`
}

type mppAuthorizationWire struct {
	Type        string `json:"type"`
	From        string `json:"from"`
	To          string `json:"to"`
	Value       string `json:"value"`
	ValidAfter  string `json:"validAfter"`
	ValidBefore string `json:"validBefore"`
	Nonce       string `json:"nonce"`
	Signature   string `json:"signature"`
}

var (
	b64urlRE      = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	challengeIDRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	tokenRE       = regexp.MustCompile(`^[a-z0-9-]{1,64}$`)
	printableRE   = regexp.MustCompile(`^[\x20-\x7e]*$`)
)

func boundedPrintable(p *string, max int, required bool) bool {
	if p == nil {
		return !required
	}
	return (!required || *p != "") && len(*p) <= max && printableRE.MatchString(*p)
}

// Parse reads an MPP credential (the base64url after "Payment "): the
// echoed challenge, an optional source, and an evm "authorization" payload
// whose fields are as strict as x402's. Unknown fields are ignored, as the
// spec requires; duplicate keys, bad UTF-8, padding and anything out of
// bounds are payment_invalid. field is the header it came in.
func (w mppWire) Parse(raw, field string) (Auth, error) {
	return parseMPP(raw, field)
}

func parseMPP(raw, field string) (Auth, error) {
	invalid := refusal(CodeInvalid)
	if field != headerAuthorization && field != headerPaymentAuthorization {
		return Auth{}, invalid
	}
	if raw == "" || len(raw) > MPPCredentialBytes || !b64urlRE.MatchString(raw) {
		return Auth{}, invalid
	}
	js, err := base64.RawURLEncoding.Strict().DecodeString(raw)
	if err != nil {
		return Auth{}, invalid
	}
	var cw mppCredentialWire
	if lenientObject(js, &cw) != nil || !IsObject(cw.Challenge) || !IsObject(cw.Payload) {
		return Auth{}, invalid
	}
	if cw.Source != nil && (len(*cw.Source) > 256 || !printableRE.MatchString(*cw.Source)) {
		return Auth{}, invalid
	}
	var ew mppEchoWire
	if lenientObject(cw.Challenge, &ew) != nil {
		return Auth{}, invalid
	}
	if ew.ID == nil || !challengeIDRE.MatchString(*ew.ID) || !boundedPrintable(ew.Realm, 255, true) ||
		ew.Method == nil || !tokenRE.MatchString(*ew.Method) || ew.Intent == nil || !tokenRE.MatchString(*ew.Intent) ||
		ew.Request == nil || len(*ew.Request) > 4096 || !b64urlRE.MatchString(*ew.Request) ||
		!boundedPrintable(ew.Expires, 64, false) || !boundedPrintable(ew.Digest, 256, false) || !boundedPrintable(ew.Header, 64, false) ||
		(ew.Opaque != nil && (len(*ew.Opaque) > 1024 || !b64urlRE.MatchString(*ew.Opaque))) ||
		(ew.Description != nil && len(*ew.Description) > 4096) {
		return Auth{}, invalid
	}
	quote := ""
	if ew.Opaque != nil {
		ob, err := base64.RawURLEncoding.Strict().DecodeString(*ew.Opaque)
		if err != nil {
			return Auth{}, invalid
		}
		var m map[string]string // a flat string-to-string map, as the spec requires
		if lenientObject(ob, &m) != nil {
			return Auth{}, invalid
		}
		if q, ok := m["q"]; ok {
			if !quoteRE.MatchString(q) {
				return Auth{}, invalid
			}
			quote = q
		}
	}
	var pw mppAuthorizationWire
	if lenientObject(cw.Payload, &pw) != nil || pw.Type != mppCredentialType {
		return Auth{}, invalid
	}
	x := Auth{Wire: WireMPP, Quote: quote, Ref: *ew.ID, Field: field,
		mpp: &mppEcho{ID: *ew.ID, Realm: *ew.Realm, Method: *ew.Method, Intent: *ew.Intent, Request: *ew.Request,
			Expires: ew.Expires, Digest: ew.Digest, Opaque: ew.Opaque, Header: ew.Header}}
	a := X402AuthorizationWire{From: pw.From, To: pw.To, Value: pw.Value, ValidAfter: pw.ValidAfter, ValidBefore: pw.ValidBefore, Nonce: pw.Nonce}
	if !parseAuthorization(a, pw.Signature, &x.From, &x.To, &x.Value, &x.ValidAfter, &x.ValidBefore, &x.Nonce, &x.Signature) {
		return Auth{}, invalid
	}
	return x, nil
}

// sameOptional says an echoed optional parameter is exactly ours: present
// with our value when we sent it, absent when we did not.
func sameOptional(echo *string, want string) bool {
	if want == "" {
		return echo == nil
	}
	return echo != nil && *echo == want
}

// Bound holds an MPP credential to the challenge a rebuilds: the echoed
// parameters must be ours byte for byte and the id our HMAC over them
// (payment_challenge when not, payment_mismatch when the request or body
// differs), the challenge unexpired (payment_expired), the credential in
// the field the challenge selected, and the authorization exactly the
// request: to = recipient, value = amount, nonce = keccak256(id ‖ realm),
// valid now and for ValidBeforeMargin more seconds. The asset and chain
// are the request's, which the id covers, and the facilitator verifies
// the signature against our own requirement.
func (w mppWire) Bound(x Auth, a Ask, now int64) error {
	if x.Wire != WireMPP || x.mpp == nil {
		return refusal(CodeInvalid)
	}
	want, err := w.build(a)
	if err != nil {
		return refusal(CodeMismatch)
	}
	e := x.mpp
	switch {
	case e.Realm != want.Realm || e.Method != want.Method || e.Intent != want.Intent:
		return refusal(CodeChallenge)
	case e.Request != want.Request || !sameOptional(e.Digest, want.Digest):
		return refusal(CodeMismatch)
	case !sameOptional(e.Expires, want.Expires) || !sameOptional(e.Opaque, want.Opaque) || !sameOptional(e.Header, want.Header):
		return refusal(CodeChallenge)
	case !hmac.Equal([]byte(e.ID), []byte(want.ID)):
		return refusal(CodeChallenge)
	}
	wantField := headerAuthorization
	if want.Header != "" {
		wantField = want.Header
	}
	if x.Field != wantField {
		return refusal(CodeChallenge)
	}
	if a.Expires < now {
		return refusal(CodeExpired)
	}
	if x.To != a.PayTo || x.Value != a.Amount || x.Nonce != challengeNonceHex(want.ID, want.Realm) {
		return refusal(CodeMismatch)
	}
	return checkWindow(a.Expires, x.ValidAfter, x.ValidBefore, now)
}

// Receipt sets Payment-Receipt (the evm charge receipt, JCS, base64url) and
// Cache-Control: private. Call it only after settlement: the spec issues a
// receipt only for a transaction included in a block.
func (w mppWire) Receipt(s Settlement, h http.Header) error {
	if !txHashRE.MatchString(s.Transaction) || !challengeIDRE.MatchString(s.Ref) || s.At <= 0 {
		return errors.New("pay: receipt needs a transaction, a challenge id and a time")
	}
	raw, err := jcs.Encode(map[string]any{
		"challengeId": s.Ref,
		"chainId":     w.chainID,
		"method":      mppMethod,
		"reference":   strings.ToLower(s.Transaction),
		"status":      "success",
		"timestamp":   time.Unix(s.At, 0).UTC().Format(time.RFC3339),
	})
	if err != nil {
		return err
	}
	h.Set(headerPaymentReceipt, base64.RawURLEncoding.EncodeToString(raw))
	h.Set("Cache-Control", "private")
	return nil
}

// mppProblems maps the board's payment error codes to the spec's problem
// types (one table: §Error Codes of draft-httpauth-payment-01).
var mppProblems = map[string]struct {
	slug, title string
	status      int
}{
	"payment_required":  {"payment-required", "Payment Required", 402},
	CodeInvalid:         {"malformed-credential", "Malformed Credential", 402},
	CodeChallenge:       {"invalid-challenge", "Invalid Challenge", 402},
	"payment_replayed":  {"invalid-challenge", "Invalid Challenge", 402},
	CodeExpired:         {"payment-expired", "Payment Expired", 402},
	CodeMismatch:        {"verification-failed", "Payment Verification Failed", 402},
	"payment_rejected":  {"verification-failed", "Payment Verification Failed", 402},
	"payment_unsettled": {"internal-payment-error", "Internal Payment Error", 500},
}

// Problem is the RFC 9457 body for a board payment error code; a code with
// no MPP problem type is the zero Problem (the board's error stands).
func (w mppWire) Problem(code, detail string) Problem {
	p, ok := mppProblems[code]
	if !ok {
		return Problem{}
	}
	body := map[string]any{"type": ProblemBase + p.slug, "title": p.title, "status": p.status}
	if detail != "" {
		body["detail"] = detail
	}
	return Problem{Status: p.status, Body: body}
}

// MPPChallenge is a Payment challenge as a client reads it: its
// parameters, unescaped.
type MPPChallenge struct {
	Params map[string]string
}

// ParseMPPChallenges reads the Payment challenges in WWW-Authenticate field
// values (RFC 9110 §11: a list of challenges, each a scheme and
// auth-params), skipping other schemes. Each value is bounded by
// MPPChallengeBytes; a malformed value is an error. A challenge without a
// non-empty id, realm, method, intent and request is refused, as the spec
// requires.
func ParseMPPChallenges(values []string) ([]MPPChallenge, error) {
	var out []MPPChallenge
	for _, v := range values {
		if len(v) > MPPChallengeBytes {
			return nil, errors.New("pay: challenge too large")
		}
		cs, err := parseAuthenticate(v)
		if err != nil {
			return nil, err
		}
		for _, c := range cs {
			if !strings.EqualFold(c.scheme, mppScheme) {
				continue
			}
			for _, k := range []string{"id", "realm", "method", "intent", "request"} {
				if c.params[k] == "" {
					return nil, errors.New("pay: Payment challenge without " + k)
				}
			}
			out = append(out, MPPChallenge{Params: c.params})
		}
	}
	return out, nil
}

type authChallenge struct {
	scheme string
	params map[string]string
}

// parseAuthenticate is a strict RFC 9110 WWW-Authenticate parser for
// auth-param challenges (token68 challenges are refused): duplicate
// parameters are an error.
func parseAuthenticate(v string) ([]authChallenge, error) {
	bad := errors.New("pay: malformed WWW-Authenticate")
	var out []authChallenge
	i, n := 0, len(v)
	skipWS := func() {
		for i < n && (v[i] == ' ' || v[i] == '\t') {
			i++
		}
	}
	token := func() string {
		start := i
		for i < n && isTchar(v[i]) {
			i++
		}
		return v[start:i]
	}
	for {
		skipWS()
		for i < n && v[i] == ',' { // empty list elements
			i++
			skipWS()
		}
		if i >= n {
			break
		}
		scheme := token()
		if scheme == "" {
			return nil, bad
		}
		c := authChallenge{scheme: scheme, params: map[string]string{}}
		skipWS()
		for i < n {
			save := i
			name := token()
			skipWS()
			if name == "" || i >= n || v[i] != '=' {
				// Not an auth-param: the next challenge starts here.
				i = save
				break
			}
			i++ // '='
			skipWS()
			var val string
			if i < n && v[i] == '"' {
				i++
				var b strings.Builder
				for {
					if i >= n {
						return nil, bad
					}
					ch := v[i]
					if ch == '"' {
						i++
						break
					}
					if ch == '\\' {
						i++
						if i >= n {
							return nil, bad
						}
						ch = v[i]
					}
					if ch < 0x20 && ch != '\t' || ch == 0x7f {
						return nil, bad
					}
					b.WriteByte(ch)
					i++
				}
				val = b.String()
			} else {
				val = token()
				if val == "" {
					return nil, bad
				}
			}
			key := strings.ToLower(name)
			if _, dup := c.params[key]; dup {
				return nil, bad
			}
			c.params[key] = val
			skipWS()
			if i < n {
				if v[i] != ',' {
					return nil, bad
				}
				i++
				skipWS()
			}
		}
		out = append(out, c)
	}
	return out, nil
}

func isTchar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0
}

// Nonce is the EIP-3009 nonce a credential for c must sign:
// "0x" + hex(keccak256(id ‖ realm)).
func (c MPPChallenge) Nonce() string { return challengeNonceHex(c.Params["id"], c.Params["realm"]) }

// Request is c's decoded request object.
func (c MPPChallenge) Request() (map[string]any, error) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(c.Params["request"])
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := lenientObject(raw, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// Credential is the header value ("Payment " + base64url JSON) answering c
// with a signed EIP-3009 authorization: the challenge echoed unchanged
// (every parameter it carried that the spec names), the payload, and an
// optional source DID.
func (c MPPChallenge) Credential(a X402AuthorizationWire, signature, source string) (string, error) {
	echo := map[string]string{}
	for _, k := range []string{"id", "realm", "method", "intent", "request", "description", "opaque", "digest", "expires", "header"} {
		if v, ok := c.Params[k]; ok {
			echo[k] = v
		}
	}
	cred := map[string]any{"challenge": echo, "payload": map[string]string{
		"type": mppCredentialType, "from": a.From, "to": a.To, "value": a.Value,
		"validAfter": a.ValidAfter, "validBefore": a.ValidBefore, "nonce": a.Nonce, "signature": signature}}
	if source != "" {
		cred["source"] = source
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(cred); err != nil {
		return "", err
	}
	return mppScheme + " " + base64.RawURLEncoding.EncodeToString(bytes.TrimRight(b.Bytes(), "\n")), nil
}
