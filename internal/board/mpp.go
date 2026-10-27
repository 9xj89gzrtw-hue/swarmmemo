package board

// MPP beside x402 (C202b; research/mpp-design.md): while MPP is on, credit
// top-ups and agent offerings write both challenges in one 402 (x402's
// PAYMENT-REQUIRED and MPP's WWW-Authenticate: Payment, through pay.Offer)
// and take either credential back. Both carry one EIP-3009 authorization of
// USDC on Base, so both settle on the one rail, through the same
// facilitator calls (Verify, SettleVerified), unchanged.
//
// Binding. The MPP challenge carries the board's own quote ("EXPIRES.SALT.
// MAC", the same one x402's extra.quote carries) in opaque {"q": quote}, and
// its id is an HMAC over every parameter under a key derived from the quote
// key (pay.NewMPP). At intake the board checks the echoed quote with its own
// key first, rebuilds the ask the quote stands for, and the wire binds the
// credential to it (Bound: the id, the echoed parameters, the header, the
// amount, the recipient, nonce = keccak256(id ‖ realm), the time window).
// Then the rows are the x402 ones: the nonce is UNIQUE, so one challenge
// pays once. A row records its wire (protocol) and, for MPP, the challenge
// id its receipt names (payment_ref).
//
// Off (the default), nothing here runs and nothing on the wire changes.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	paywire "swarmmemo/internal/pay"
	"swarmmemo/internal/services"
)

// paymentColumns32 are the schema-32 columns of credit_topups and
// offering_calls, in the order they are added (a keyed column step, so a
// new database and an upgraded one end with the same tables).
var paymentColumns32 = []struct{ name, decl string }{
	{"protocol", "TEXT NOT NULL DEFAULT 'x402' CHECK(protocol IN ('x402','mpp'))"},
	{"payment_ref", "TEXT NOT NULL DEFAULT ''"},
}

// migratePaymentProtocol32 adds protocol and payment_ref to credit_topups
// and offering_calls. Every earlier row was an x402 payment, hence the
// default.
func migratePaymentProtocol32(tx *sql.Tx) error {
	for _, table := range []string{"credit_topups", "offering_calls"} {
		for _, column := range paymentColumns32 {
			var exists int
			if err := tx.QueryRow("SELECT count(*) FROM pragma_table_info(?) WHERE name=?", table, column.name).Scan(&exists); err != nil {
				return err
			}
			if exists == 0 {
				if _, err := tx.Exec("ALTER TABLE " + table + " ADD COLUMN " + column.name + " " + column.decl); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// mppState is MPP's wire per product: nil while MPP is off or the product
// is.
type mppState struct {
	topup, offerings paywire.Wire
}

// openMPP builds the MPP wires while MPP is on: realm is SERVICE_ID, the
// challenge key derived from the quote key. A wire that cannot be built
// stops the start, so MPP=on never runs half on.
func (s *Store) openMPP() error {
	if !s.config.Features.MPP {
		return nil
	}
	build := func(cfg *services.TopupConfig) (paywire.Wire, error) {
		w, err := paywire.NewMPP(cfg.Rail(), s.config.ServiceID, s.topupKey)
		if err != nil {
			return nil, fmt.Errorf("MPP=on: %w", err)
		}
		return w, nil
	}
	var err error
	if s.TopupEnabled() {
		if s.mpp.topup, err = build(s.config.Topup); err != nil {
			return err
		}
	}
	if s.OfferingsEnabled() {
		if s.mpp.offerings, err = build(s.config.Offerings); err != nil {
			return err
		}
	}
	return nil
}

// MPPEnabled reports whether MPP is on for a product that takes payments:
// the HTTP adapter then reads MPP credentials and writes MPP headers.
func (s *Store) MPPEnabled() bool { return s.mpp.topup != nil || s.mpp.offerings != nil }

// ---- the credential a request carries -----------------------------------

type paymentKey struct{}

// paymentCred is the payment credential a paid command carries: x402's
// base64 payload, or MPP's base64url credential and the header it came in
// (a data.payment credential counts as Authorization).
type paymentCred struct {
	wire, raw, field string
}

// value is the credential as data.payment carries it: x402's payload, or
// "Payment " and MPP's credential.
func (c paymentCred) value() string {
	if c.raw == "" {
		return ""
	}
	if c.wire == paywire.WireMPP {
		return "Payment " + c.raw
	}
	return c.raw
}

// WithPayment records the x402 payment header an HTTP request carried
// (PAYMENT-SIGNATURE or X-PAYMENT), for credits.topup and offering.buy. It
// is outside the signed envelope: the payment is itself signed by the
// payer, and the quote it accepts binds it to the account and the amount.
func WithPayment(ctx context.Context, header string) context.Context {
	return context.WithValue(ctx, paymentKey{}, paymentCred{wire: paywire.WireX402, raw: header})
}

// WithMPPPayment records the MPP credential an HTTP request carried
// (Authorization: Payment, or Payment-Authorization), as WithPayment does
// x402's: raw is the base64url after "Payment ", field the header.
func WithMPPPayment(ctx context.Context, raw, field string) context.Context {
	return context.WithValue(ctx, paymentKey{}, paymentCred{wire: paywire.WireMPP, raw: raw, field: field})
}

// withoutPayment is ctx with no payment header: the same request asking
// for a quote.
func withoutPayment(ctx context.Context) context.Context {
	return context.WithValue(ctx, paymentKey{}, paymentCred{})
}

func paymentCredFrom(ctx context.Context) paymentCred {
	v, _ := ctx.Value(paymentKey{}).(paymentCred)
	return v
}

func paymentFrom(ctx context.Context) string { return paymentCredFrom(ctx).value() }

// PaymentWire is the wire of the payment header ctx carries (pay.WireX402
// or pay.WireMPP), or "".
func PaymentWire(ctx context.Context) string {
	if c := paymentCredFrom(ctx); c.raw != "" {
		return c.wire
	}
	return ""
}

// dataCred is data.payment as a credential: MPP's when it reads
// "Payment …" and the product's MPP wire w is on, else x402's (as before
// MPP: anything else is an x402 payload, and refused as one if it is not).
func dataCred(data string, w paywire.Wire) paymentCred {
	if w != nil {
		if tok, ok := paywire.MPPToken(data); ok {
			return paymentCred{wire: paywire.WireMPP, raw: tok, field: paywire.MPPAuthorizationField}
		}
	}
	return paymentCred{wire: paywire.WireX402, raw: data}
}

// requestCred is the credential a paid command carries: the header's
// (data.payment, when also given, must be the same credential) or
// data.payment's. An MPP header while the product's MPP wire is off is
// refused.
func requestCred(ctx context.Context, data string, w paywire.Wire) (paymentCred, error) {
	cred := dataCred(data, w)
	if h := paymentCredFrom(ctx); h.raw != "" {
		if data != "" && data != h.value() {
			return paymentCred{}, problem(400, "payment_invalid", "The payment header and data.payment differ; send one.")
		}
		cred = h
	}
	if cred.wire == paywire.WireMPP && w == nil {
		return paymentCred{}, problem(400, "payment_invalid", "This server takes x402 payments here, not MPP; see /capabilities.")
	}
	return cred, nil
}

// credQuote is the quote a credential echoes, or "" when it does not
// parse.
func credQuote(c paymentCred) string {
	if c.wire == paywire.WireMPP {
		if x, err := paywire.ParseMPPCredential(c.raw, c.field); err == nil {
			return x.Quote
		}
		return ""
	}
	if p, err := services.ParseTopupPayment(c.raw); err == nil {
		return p.Quote
	}
	return ""
}

// ---- intake --------------------------------------------------------------

// mppIntake reads an MPP credential and binds it: the wire parses it, check
// verifies the quote it echoes with the board's key and returns the ask that
// quote stands for, and the wire holds the credential to that ask. The
// payment returned is the authorization for the facilitator; ref is the
// challenge id. Nothing has moved when it refuses.
func mppIntake(w paywire.Wire, c paymentCred, now int64, offering bool, check func(quote string) (paywire.Ask, error)) (services.TopupPayment, string, error) {
	x, err := w.Parse(c.raw, c.field)
	if err != nil {
		return services.TopupPayment{}, "", mppRefusal(err, offering)
	}
	ask, err := check(x.Quote)
	if err != nil {
		return services.TopupPayment{}, "", err
	}
	if err = w.Bound(x, ask, now); err != nil {
		return services.TopupPayment{}, "", mppRefusal(err, offering)
	}
	return x.Payment(), x.Ref, nil
}

// mppRefusal is a wire's refusal of an MPP credential as the board's
// error: payment_invalid and payment_challenge in MPP's words, the rest as
// x402's (topupError, offeringPaymentError).
func mppRefusal(err error, offering bool) error {
	var r *paywire.Refusal
	if !errors.As(err, &r) {
		return err
	}
	switch r.Code {
	case paywire.CodeInvalid:
		return problem(400, "payment_invalid", fmt.Sprintf("The credential is not one MPP Payment credential (method evm, intent charge, payload type authorization) in base64url, of at most %d bytes.", paywire.MPPCredentialBytes))
	case paywire.CodeChallenge:
		return problem(400, "payment_challenge", "The credential does not answer a challenge this server issued, unchanged and in the header it named; ask again without a payment for a fresh challenge.")
	}
	te := &services.TopupError{Code: r.Code, Definite: true}
	if offering {
		return offeringPaymentError(te)
	}
	return topupError(te)
}

// withFreshChallenge answers an MPP credential's refusal as MPP asks: with
// a fresh challenge beside the problem. fresh is the same command without
// its payment; when it answers payment_required (a quote within the
// limits), its details ride along with the refusal's code and message.
func withFreshChallenge(err error, fresh func() error) error {
	var be *Error
	if !errors.As(err, &be) || be.Details != nil || paywire.MPPProblem(be.Code, "").Status != http.StatusPaymentRequired {
		return err
	}
	var fe *Error
	if !errors.As(fresh(), &fe) || fe.Code != "payment_required" {
		return err
	}
	return &Error{Status: be.Status, Code: be.Code, Message: be.Message, RetryAfter: be.RetryAfter, NextOpenAt: be.NextOpenAt, Details: fe.Details}
}

// ---- the 402 and the receipt ---------------------------------------------

// offerMPP writes the 402's challenges on both wires through pay.Offer (all
// or nothing) into details: x402's PaymentRequired object and header, as
// before, and MPP's WWW-Authenticate value. It says whether MPP is in;
// while w is nil, or should the challenge fail, details keep x402's alone.
func offerMPP(w paywire.Wire, cfg *services.TopupConfig, ask paywire.Ask, details map[string]any) bool {
	if w == nil {
		return false
	}
	h := http.Header{}
	off, err := paywire.Offer(ask, h, paywire.NewX402(cfg.Rail()), w)
	if err != nil || len(h.Values("WWW-Authenticate")) != 1 {
		slog.Error("MPP challenge not offered; x402 alone", "error", fmt.Sprint(err))
		return false
	}
	details["x402"] = off.Bodies[paywire.WireX402]
	details["payment_required"] = h.Get("PAYMENT-REQUIRED")
	details["mpp"] = map[string]any{"www_authenticate": h.Get("WWW-Authenticate"), "challenge_id": off.Bodies[paywire.WireMPP]["challengeId"]}
	return true
}

// mppReceipt is the Payment-Receipt value of a settled MPP payment: the
// transaction, the challenge id ref and when it settled; "" when w is off or
// the terms are incomplete.
func mppReceipt(w paywire.Wire, tx, payer, ref string, at int64) string {
	if w == nil || ref == "" || tx == "" {
		return ""
	}
	from, _ := services.ParseEVMAddress(payer)
	h := http.Header{}
	if err := w.Receipt(paywire.Settlement{Transaction: tx, Payer: from, Ref: ref, At: at}, h); err != nil {
		return ""
	}
	return h.Get("Payment-Receipt")
}

// mppTerms is the MPP object top-ups and offerings list beside x402 while
// MPP is on: how to pay with it.
func (s *Store) mppTerms(cfg *services.TopupConfig) map[string]any {
	chain, _ := cfg.Rail().ChainID()
	return map[string]any{
		"spec": "draft-httpauth-payment-01 (evm charge, draft-evm-charge-00)", "scheme": "Payment", "method": "evm", "intent": "charge", "credential_type": "authorization",
		"chain_id": chain, "currency": cfg.Asset.String(), "realm": s.config.ServiceID,
		"headers":      map[string]string{"challenge": "WWW-Authenticate: Payment", "credential": "Authorization: Payment", "receipt": "Payment-Receipt"},
		"nonce":        "keccak256(challenge.id ‖ realm): an EIP-3009 authorization answers one challenge",
		"binding":      "the challenge id is an HMAC over every parameter; opaque {\"q\": quote} carries the board's quote; send the challenge back unchanged",
		"errors":       "application/problem+json, https://paymentauth.org/problems/*, a fresh challenge with each refusal; two credentials are 400",
		"data_payment": "\"Payment BASE64URL\" (signed commands and MCP)",
	}
}

// MPPDiscovery is the MPP entry of /openapi.json's x-payment-info.protocols
// for agent offerings (the agentcash/x402scan shape: method, intent,
// currency); nil while MPP is off for them.
func (s *Store) MPPDiscovery() map[string]any {
	if s.mpp.offerings == nil {
		return nil
	}
	return map[string]any{"method": "evm", "intent": "charge", "currency": s.config.Offerings.Asset.String()}
}
