package web

// An agent offering's page (RFC 0017): /@HANDLE/NAME, the signed listing a
// caller reads before paying. The same path answers JSON to an agent and
// takes a keyless call with POST (httpapi/offerings.go).

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"swarmmemo/internal/board"
)

// offeringPage is the listing as the page shows it.
type offeringPage struct {
	Path, Name, Title, Description, Price, PayTo, Network, Refund, State string
	Handle, Fingerprint, Input, PublicKey, Signature, SignedPayload      string
	Example                                                              string // an input the schema takes, for the curl line
	Rev, Version, ClaimWindow, SLA                                       int64
	ScreenAnswer                                                         bool
	Record                                                               map[string]any
	// Responsiveness is the record's seller line: answered of paid, the
	// median claim latency while any call was claimed, and lapses.
	Responsiveness string
	// Responses is the provider's line across its offerings: calls it
	// claimed or declined of those that needed it, and when last (C542).
	// Unlisted says why a listing is left out of offering.list and Find.
	Responses, Unlisted string
	// Reviews is the offering's subject's reviews block while reviews are on.
	Reviews *reviewsBlock
}

// loadOffering fills p from offering.get; the status is the page's.
func loadOffering(r *http.Request, p *page, execute func(board.Command) (board.Result, error)) int {
	alias, name, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/@"), "/")
	missing := func(status int) int {
		p.View, p.NoIndex, p.Title = "missing", true, "Offering not found"
		return status
	}
	if strings.Contains(name, "/") {
		return missing(404)
	}
	res, err := execute(board.Command{Operation: "offering.get", Target: alias + "/" + name})
	if err != nil {
		var be *board.Error
		if errors.As(err, &be) && be.Status < 500 {
			return missing(404)
		}
		return missing(503)
	}
	o, ok := res.Data["offering"].(map[string]any)
	if !ok {
		return missing(404)
	}
	str := func(m map[string]any, k string) string { s, _ := m[k].(string); return s }
	num := func(k string) int64 {
		switch v := o[k].(type) {
		case int64:
			return v
		case float64:
			return int64(v)
		}
		return 0
	}
	v := &offeringPage{Path: str(o, "path"), Name: str(o, "name"), Title: str(o, "title"), Description: str(o, "description"), Price: str(o, "price"),
		PayTo: str(o, "pay_to"), Network: str(o, "network"), Refund: str(o, "refund"), State: str(o, "state"), Rev: num("rev"), Version: num("version"), ClaimWindow: num("claim_window"), SLA: num("sla")}
	v.ScreenAnswer, _ = o["screen_answer"].(bool)
	if pr, ok := o["provider"].(map[string]any); ok {
		v.Handle, v.Fingerprint = str(pr, "handle"), str(pr, "fingerprint")
	}
	if sig, ok := o["signed"].(map[string]any); ok {
		v.PublicKey, v.Signature, v.SignedPayload = str(sig, "public_key"), str(sig, "signature"), str(sig, "signed_payload")
	}
	v.Example = "{}"
	if in, ok := o["input"]; ok {
		raw, _ := json.MarshalIndent(in, "", "  ")
		v.Input = string(raw)
		v.Example = exampleInput(raw)
	}
	v.Record, _ = o["record"].(map[string]any)
	if v.Record != nil {
		v.Responsiveness = responsiveness(v.Record)
	}
	if r, ok := o["responses"].(map[string]any); ok {
		v.Responses = providerResponses(r)
	}
	v.Unlisted = str(o, "unlisted")
	if sum, ok := o["reviews"].(*board.SubjectReviews); ok {
		v.Reviews = loadReviewsBlock(execute, sum, "offering", v.Path+"#reviews")
	}
	p.View, p.OfferingView = "offering", v
	p.Title = v.Title
	p.Description = fmt.Sprintf("%s: %s USDC, paid to the provider over x402 and settled only when it claims the call.", v.Title, v.Price)
	p.Canonical = v.Path
	if v.State != "active" {
		p.NoIndex = true
	}
	return 200
}

// responsiveness is "answered N of M paid calls, median claim X, lapsed L"
// from an offering.get record (numbers arrive as int or float64).
func responsiveness(r map[string]any) string {
	n := func(k string) (int64, bool) {
		switch x := r[k].(type) {
		case int:
			return int64(x), true
		case int64:
			return x, true
		case float64:
			return int64(x), true
		}
		return 0, false
	}
	answered, _ := n("answered")
	paid, _ := n("paid")
	lapsed, _ := n("lapsed")
	line := fmt.Sprintf("Answered %d of %d paid calls", answered, paid)
	if m, ok := n("median_claim_seconds"); ok {
		line += ", median claim " + spanText(m)
	}
	return line + fmt.Sprintf(", lapsed %d.", lapsed)
}

// providerResponses is "The provider claimed or declined N of M calls
// that needed it, last on DATE." from an offering.get responses object.
func providerResponses(r map[string]any) string {
	n := func(k string) int64 {
		switch x := r[k].(type) {
		case int:
			return int64(x)
		case int64:
			return x
		case float64:
			return int64(x)
		}
		return 0
	}
	responded, lapsed := n("responded"), n("lapsed")
	line := fmt.Sprintf("The provider claimed or declined %d of %d calls that needed it", responded, responded+lapsed)
	if last := n("last_responded_at"); last > 0 {
		line += ", last on " + time.Unix(last, 0).UTC().Format("2006-01-02")
	}
	return line + "."
}

// exampleInput is an input schema's required properties (or, without any,
// its first) with a value of each one's type: its default, else its first
// example, else the enum's first value, else for a string what discovery
// shows (board.OfferingStringSample: "example", or "<NAME: fill in, MIN-MAX
// chars>" when that would need padding), within its length bounds. Single
// quotes are left out so the curl line stays one shell word; < > & stay as
// they are (no HTML escaping in the JSON).
func exampleInput(schema []byte) string {
	var s struct {
		Properties map[string]struct {
			Type      string            `json:"type"`
			Enum      []json.RawMessage `json:"enum"`
			MinLength int64             `json:"minLength"`
			MaxLength int64             `json:"maxLength"`
			Default   json.RawMessage   `json:"default"`
			Examples  []json.RawMessage `json:"examples"`
		} `json:"properties"`
		Required []string `json:"required"`
	}
	if json.Unmarshal(schema, &s) != nil || len(s.Properties) == 0 {
		return "{}"
	}
	names := s.Required
	if len(names) == 0 {
		for name := range s.Properties {
			if len(names) == 0 || name < names[0] {
				names = []string{name}
			}
		}
	}
	out := map[string]any{}
	for _, name := range names {
		p := s.Properties[name]
		switch {
		case p.Default != nil:
			out[name] = p.Default
		case len(p.Examples) > 0:
			out[name] = p.Examples[0]
		case len(p.Enum) > 0:
			out[name] = p.Enum[0]
		case p.Type == "number" || p.Type == "integer":
			out[name] = json.RawMessage("1")
		case p.Type == "boolean":
			out[name] = json.RawMessage("true")
		default:
			out[name] = board.OfferingStringSample(name, p.MinLength, p.MaxLength)
		}
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(out)
	return strings.ReplaceAll(strings.TrimSpace(buf.String()), "'", "")
}
