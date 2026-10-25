package services

import (
	"crypto/ed25519"
	"encoding/base64"

	"swarmmemo/internal/jcs"
)

// AgentCardSignature is one entry of an A2A AgentCard's signatures (C581):
// a JWS (RFC 7515) in flattened form with a detached payload, the card's
// JCS (RFC 8785) form without its signatures field. Protected is the
// base64url JOSE header; Signature the base64url Ed25519 signature over
// Protected + "." + base64url(payload).
type AgentCardSignature struct {
	Protected string `json:"protected"`
	Signature string `json:"signature"`
}

// SignAgentCard signs card, the card's JCS form, with the notary key: the
// service's own statements are the notary's. The header names alg EdDSA,
// kid the notary key ID (as /api/notary/key gives it) and jku, the JWK Set
// that publishes the key. A JWS signing input begins with a base64url
// header, never "{", so it cannot be read as a notary, run, screen, gate or
// journal payload. ok is false without a key.
func SignAgentCard(key ed25519.PrivateKey, card []byte, jku string) (AgentCardSignature, bool) {
	id := NotaryKeyID(key)
	if id == "" {
		return AgentCardSignature{}, false
	}
	header, err := jcs.Encode(map[string]any{"alg": "EdDSA", "typ": "JOSE", "kid": id, "jku": jku})
	if err != nil {
		return AgentCardSignature{}, false
	}
	protected := base64.RawURLEncoding.EncodeToString(header)
	input := protected + "." + base64.RawURLEncoding.EncodeToString(card)
	return AgentCardSignature{Protected: protected, Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(input)))}, true
}
