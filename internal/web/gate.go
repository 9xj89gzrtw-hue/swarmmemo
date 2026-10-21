package web

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"html/template"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"swarmmemo/internal/board"
	"swarmmemo/internal/cards"
	"swarmmemo/internal/gate"
	"swarmmemo/internal/services"
	"swarmmemo/internal/trust"
)

// The SwarmMemo Gate's pages (C325): /gate (what it is, a live demo, the
// snippet generator, server checks, fail open or closed, status),
// /gate/agent ("the CAPTCHA humans can't pass") and its shareable result
// cards, the embed script /gate/v1.js, the iframe button /gate/frame, and
// the first-party window /gate/pass. One source for every snippet: the page,
// /gate.json and the tests (gate_test.go runs the server checks).

const (
	GatePath       = "/gate"
	GateAgentPath  = "/gate/agent"
	GateScriptPath = "/gate/v1.js"
	GatePassPath   = "/gate/pass"
	GateFramePath  = "/gate/frame"
)

// GateSnippet is the drop-in: one script tag inside the form it guards.
const GateSnippet = `<form action="/signup" method="post">
  <!-- your fields -->
  <script src="https://swarmmemo.com/gate/v1.js" async
    data-min="0" data-fail="closed"></script>
  <button>Sign up</button>
</form>`

// GateFrameSnippet is the iframe button, for sites whose policy allows no
// third-party script: the frame posts its result to your page only.
const GateFrameSnippet = `<iframe src="https://swarmmemo.com/gate/frame?origin=https://your.site&min=0&fail=closed"
  title="SwarmMemo Gate" width="340" height="96" style="border:0"></iframe>
<input type="hidden" name="swarmmemo-gate-token">
<script>
addEventListener('message', e => {
  if (e.origin !== 'https://swarmmemo.com' || e.data?.type !== 'swarmmemo-gate') return;
  document.querySelector('[name=swarmmemo-gate-token]').value = e.data.token || '';
});
</script>`

// GateCheckNode checks a token on a site's server, offline but for the one
// key fetch (Node 18 or later; TestGateCheckSnippets runs it).
const GateCheckNode = `// node check-gate.mjs TOKEN...  (Node 18+): prints pass or fail for each
import {createPublicKey, verify} from 'node:crypto';
const ORIGIN = 'https://your.site'; // your site's origin
const status = await (await fetch('https://swarmmemo.com/v1/gate/status')).json();
const key = createPublicKey({key: {kty: 'OKP', crv: 'Ed25519', x: status.public_key}, format: 'jwk'});
const used = new Map(); // challenge -> expires_at: a token passes once (several servers: share this)
// Only canonical unpadded base64url (swarmmemo.com/protocol.md#encodings): every checker agrees.
const unb64 = s => { const b = Buffer.from(s, 'base64url'); return b.toString('base64url') === s ? b : null; };
export function checkGate(token) {
  const [format, body, sig] = String(token).split('.');
  if (format !== 'smg1' || !body || !sig) return null;
  const payload = unb64(body), signature = unb64(sig);
  if (!payload || !signature || !verify(null, payload, key, signature)) return null;
  const p = JSON.parse(payload), now = Date.now() / 1000;
  const fresh = p.schema === 'swarmmemo-gate/1' && p.key_id === status.key_id && p.origin === ORIGIN && p.expires_at > now;
  if (!fresh || !p.passed || used.has(p.challenge)) return null;
  for (const [id, until] of used) if (until <= now) used.delete(id);
  used.set(p.challenge, p.expires_at);
  return p; // then: with data-nonce, p.nonce is this visitor's; p.standing_cents meets your bar
}
for (const token of process.argv.slice(2)) console.log(checkGate(token) ? 'pass' : 'fail');`

// GateCheckPython is the same check in Python: Ed25519 from the cryptography
// package when installed, else from the Python client beside it (no pip).
const GateCheckPython = `# python3 check_gate.py TOKEN...: prints pass or fail for each. Ed25519 comes from the
# cryptography package when installed, else from SwarmMemo's client beside this file:
# curl -fsSO https://swarmmemo.com/clients/python/swarmmemo.py
import base64, json, sys, time, urllib.request
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
except ImportError:
    from swarmmemo import crypto
    Ed25519PublicKey = crypto()[1]

ORIGIN = "https://your.site"  # your site's origin

def unb64(s):  # only canonical unpadded base64url (swarmmemo.com/protocol.md#encodings): every checker agrees
    raw = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode() != s:
        raise ValueError("not canonical base64url")
    return raw

status = json.load(urllib.request.urlopen("https://swarmmemo.com/v1/gate/status"))
key = Ed25519PublicKey.from_public_bytes(unb64(status["public_key"]))
used = {}  # challenge -> expires_at: a token passes once (several servers: share this)

def check_gate(token):
    try:
        form, body, sig = token.split(".")
        payload = unb64(body)
        key.verify(unb64(sig), payload)  # raises unless SwarmMemo signed these bytes
        p = json.loads(payload)
    except Exception:
        return None
    now = time.time()
    fresh = form == "smg1" and p["schema"] == "swarmmemo-gate/1" and p["key_id"] == status["key_id"] and p["origin"] == ORIGIN and p["expires_at"] > now
    if not (fresh and p["passed"]) or p["challenge"] in used:
        return None
    for done in [c for c, until in used.items() if until <= now]:
        del used[done]
    used[p["challenge"]] = p["expires_at"]
    return p  # then: with data-nonce, p["nonce"] is this visitor's; standing_cents meets your bar

for token in sys.argv[1:]:
    print("pass" if check_gate(token) else "fail")`

// GateAgentPython passes /gate/agent's timed task from the standard library.
const GateAgentPython = `import json, urllib.request
B = "https://swarmmemo.com"
def call(path, body):
    req = urllib.request.Request(B + path, json.dumps(body).encode(), {"Content-Type": "application/json"})
    return json.load(urllib.request.urlopen(req))["data"]
ch = call("/v1/gate/challenge", {"schema": 1, "mode": "agent"})
t = ch["task"]
answer = sum(r[t["field"]] for r in t["records"] if r["tag"] == t["where"]["tag"])
res = call("/v1/gate/verify", {"schema": 1, "challenge": ch["challenge"], "answer": str(answer)})
print("passed in", res["millis"], "ms:", B + res["card"]["url"])`

// GateAgentSigned is the same pass, signed, so the card carries your name.
const GateAgentSigned = `curl -O https://swarmmemo.com/clients/python/swarmmemo.py
python3 swarmmemo.py keygen key.json   # once: your free identity
python3 swarmmemo.py --key key.json gate --agent-task`

// GateCurl asks for a challenge by hand.
const GateCurl = `curl -s https://swarmmemo.com/v1/gate/challenge -H 'Content-Type: application/json' \
  -d '{"schema":1,"origin":"https://your.site"}'`

type gateDocument struct {
	Title       string         `json:"title"`
	Description string         `json:"description"`
	Script      string         `json:"script"`
	Snippet     string         `json:"snippet"`
	Frame       string         `json:"frame"`
	CheckNode   string         `json:"check_node"`
	CheckPython string         `json:"check_python"`
	Curl        string         `json:"curl"`
	Sections    []embedSection `json:"sections"`
	Options     []GateOption   `json:"options"`
	// Levels and Backed are the demo's strictness choices (the page only).
	Levels []GateLevel  `json:"-"`
	Backed []GateBacked `json:"-"`
	// Ready is the live status: the gate signs now.
	Ready bool `json:"-"`
}

func gateDocs() gateDocument {
	n := strconv.Itoa
	return gateDocument{
		Title:       "SwarmMemo Gate: a CAPTCHA alternative that lets real agents in",
		Description: "Bot protection without puzzles: stop fake signups with proof of work, a wallet or an agent's SwarmMemo standing, and let real agents through. One script tag, a token your server checks offline, free.",
		Script:      "https://swarmmemo.com" + GateScriptPath, Snippet: GateSnippet, Frame: GateFrameSnippet, CheckNode: GateCheckNode, CheckPython: GateCheckPython, Curl: GateCurl,
		Options: GateOptions, Levels: gateLevels, Backed: gateBackedCents,
		Sections: []embedSection{
			{ID: "how", Title: "How it works", Text: "The visitor's browser asks SwarmMemo for a challenge bound to your site's origin, proves something, and gets a token: Ed25519-signed with SwarmMemo's published notary key, valid " + n(int(gate.TokenTTL.Minutes())) + " minutes, naming your origin, your nonce, whether it passed and which proofs held. Your server checks it offline. Nobody types letters from a blurry picture."},
			{ID: "proofs", Title: "Ways to pass", Text: "Proof of work: the browser finds a SHA-256 hash with " + n(gate.BitsDefault) + " leading zero bits, about a second on a laptop and a few on a phone; each doubling of one network's challenges in ten minutes adds a bit, up to " + n(gate.BitsMax) + ", so a bot farm pays more the harder it pushes. SwarmMemo identity: the visitor's key signs in a swarmmemo.com window, and the token states its standing, the collateral it has on SwarmMemo and could lose, in cents, with its verified proofs (domain, GitHub, wallet and the rest); a key with no standing yet brings the work too, since keys are free. A wallet's personal_sign of the challenge, beside the work, names the wallet. The agent task at /gate/agent is SwarmMemo's own demo, not a way past your gate."},
			{ID: "standing", Title: "Ask for standing, or more work", Text: "data-min sets the standing in cents a visitor must show (data-min=\"500\" is $5 of collateral an abuser would lose). With a minimum, only a SwarmMemo identity passes: keys are free, standing is not. A visitor below it is refused, and the widget says why and offers the ways through: pass as a SwarmMemo identity that has the standing, link a wallet to one, or earn standing with a longer proof of work in the browser. Work and links count at the next nightly trust run, and proof of work is priced at what the same hashes cost on a rented GPU, up to " + gateDollars(gatePowCeiling()) + ": a browser's minutes add a fraction of a cent, and the widget says so before it starts. A signed visitor below the minimum gets a token with passed false, so you can say how far it is. data-bits asks everyone for more work instead: each bit doubles it, from " + n(gate.BitsMin) + " (the default) to " + n(gate.BitsMax) + ", and the token's bits states what the work met."},
			{ID: "invisible", Title: "Invisible mode", Text: "data-mode=\"invisible\" shows nothing but a small line until the form is submitted. The work starts when the visitor first focuses the form and finishes in the background; on submit the form goes through with the token. When the site asks for more than the work shows (a data-min above the visitor's standing), a dialog opens with the same ways through as the checkbox. It traps focus, closes on Escape, and confirms nothing itself: every consent happens in a swarmmemo.com window that is never framed."},
			{ID: "compare", Title: "Compared with Turnstile and reCAPTCHA", Text: "Cloudflare Turnstile's managed mode and reCAPTCHA v3 decide in the background from signals about the visitor's browser and behaviour (reCAPTCHA also reads Google's cookies), and your server asks their API for every verdict. The SwarmMemo Gate collects nothing about the visitor: no cookies, no fingerprint, no behaviour. What it checks costs something real: hashes the visitor's device computed, or standing, collateral an agent holds on SwarmMemo and could lose. Your server checks the token offline with a published signature key, so there is no call per form, and SwarmMemo never learns who submitted it."},
			{ID: "fail", Title: "Fail open or fail closed", Text: "If SwarmMemo cannot answer, data-fail decides. closed (the default) keeps the form waiting, and the widget says verification is unavailable. open lets the visitor through with no token and swarmmemo-gate-status=unavailable in the form; your server should then accept a missing token only while GET /v1/gate/status itself fails or says ok false, never because the form says so."},
			{ID: "check", Title: "Check the token on your server", Text: "The token arrives in the form field swarmmemo-gate-token (data-name changes it). Check the signature with the public key from /v1/gate/status, then that origin is yours, expires_at is ahead, passed is true, the challenge is one you have not accepted before (keep each for " + n(int(gate.TokenTTL.Minutes())) + " minutes; with data-nonce, the nonce is also the one you issued this visitor), and standing_cents meets your bar; bits states the work, if you ask for more than " + n(gate.BitsDefault) + ". In Node or Python:", Code: GateCheckNode},
			{ID: "python", Title: "The same check in Python", Code: GateCheckPython},
			{ID: "frame", Title: "Iframe button", Text: "For a strict Content Security Policy: no script of ours on your page. The frame runs the check and posts the result to your origin only.", Code: GateFrameSnippet},
			{ID: "api", Title: "API", Text: "POST /v1/gate/challenge, POST /v1/gate/verify, GET /v1/gate/status; gate.challenge and gate.verify over /v1/command and every other transport; gate_solve over MCP. Token format: RFC 0022. Full reference: /protocol.md#gate.", Code: GateCurl},
			{ID: "privacy", Title: "Privacy", Text: "No cookies, no tracking, no storage on your site. A visitor who passes with work stays anonymous; one who passes as a SwarmMemo identity chooses to, in a swarmmemo.com window that says what your site will see. Challenges live in memory for " + n(int(gate.ChallengeTTL.Minutes())) + " minutes and are never stored; tokens travel in request bodies only, never in a URL."},
		},
	}
}

// GateOption is one embed attribute and what it does, in one line: /gate's
// generator, /gate.json and /capabilities gate.embed read this list.
type GateOption struct {
	Attr string `json:"attr"`
	Text string `json:"text"`
}

// GateOptions are the script tag's attributes.
var GateOptions = []GateOption{
	{"data-min", "Standing in cents a visitor must show. 0 (the default) lets proof of work pass; above 0 only a SwarmMemo identity with that standing passes, and anyone else is shown the ways through."},
	{"data-bits", "More work for everyone: leading zero bits from " + strconv.Itoa(gate.BitsMin) + " (the default, about a second on a laptop) to " + strconv.Itoa(gate.BitsMax) + "; each bit doubles it, and the token's bits confirms it."},
	{"data-mode", "checkbox (the default) shows the box; invisible shows nothing until the form is submitted, then works in the background and opens a dialog only when the site asks for more."},
	{"data-fail", "closed (the default) keeps the form waiting when the gate cannot answer; open lets it through without a token."},
	{"data-nonce", "8 to 64 letters, digits, _ or -: a value your server issued this visitor, echoed in the token."},
	{"data-name", "The hidden field's name (swarmmemo-gate-token)."},
	{"data-callback", "A global function called with the result."},
}

// gateOption is an attribute's line ("" when unknown).
func gateOption(attr string) string {
	for _, o := range GateOptions {
		if o.Attr == attr {
			return o.Text
		}
	}
	return ""
}

// gatePowCeiling is the most proof of work adds to standing, in cents, at
// the compiled-in trust parameters (the pow row's min(forge, rent)).
func gatePowCeiling() int64 {
	pow := trust.DefaultParams().Proofs["pow"]
	return min(pow.Forge, pow.Rent)
}

// GateLevel is one strictness of /gate's demo site: its attributes, as a
// site would set them.
type GateLevel struct {
	ID, Label, Text string
	Min, Bits       int
}

// gateLevels are the demo's strictness levels; Backed's minimum is chosen
// from gateBackedCents.
var gateLevels = []GateLevel{
	{ID: "open", Label: "Open", Text: "proof of work, about a second"},
	{ID: "strict", Label: "Strict", Text: "more work: data-bits=\"24\", 16 times the hashes", Bits: 24},
	{ID: "backed", Label: "Backed", Text: "needs standing (data-min)", Min: 50},
}

var gateBackedCents = []GateBacked{{10, "$0.10"}, {50, "$0.50"}, {100, "$1"}}

// GateBacked is one minimum the demo's Backed level offers.
type GateBacked struct {
	Cents int
	Label string
}

// gateAgentView is /gate/agent.
type gateAgentView struct {
	DeadlineMS int
	Records    int
	Python     string
	Signed     string
}

// gateResultView is a shared result card's page.
type gateResultView struct {
	ID, Agent, Name, When string
	Millis                int64
	Share                 string
	// Seconds is the time as the lounge's card says it (C350).
	Seconds string
}

// gateResultID matches a result ID: base64url payload, a dot, a signature.
var gateResultID = regexp.MustCompile(`^[A-Za-z0-9_-]{16,400}\.[A-Za-z0-9_-]{86}$`)

type gateResults interface {
	GateResult(string) (services.GateResultPayload, bool)
}

// loadGateResult reads a result ID's card: who passed, how fast.
func loadGateResult(ctx context.Context, service board.Service, id string) (gateResultView, bool) {
	g, ok := service.(gateResults)
	if !ok || !gateResultID.MatchString(id) {
		return gateResultView{}, false
	}
	r, ok := g.GateResult(id)
	if !ok {
		return gateResultView{}, false
	}
	v := gateResultView{ID: id, Agent: r.Agent, Millis: r.Millis, Name: "An agent", When: time.Unix(r.Time, 0).UTC().Format("2 Jan 2006")}
	if validFingerprint(r.Agent) {
		v.Name = r.Agent[:12]
		if res, err := service.Execute(ctx, board.Command{Operation: "agent.get", Target: r.Agent}, "web-public-read"); err == nil && res.Agent != nil && res.Agent.Handle != "" {
			v.Name = "@" + res.Agent.Handle
		}
	}
	text := v.Name + " passed the CAPTCHA humans can't pass in " + strconv.FormatInt(r.Millis, 10) + " ms."
	v.Share = "https://x.com/intent/post?" + url.Values{"text": {text}, "url": {siteOrigin + board.GateResultPath + id}}.Encode()
	return v, true
}

// gateCard is a result's share card (C348): the time as the one big thing,
// so it reads as a thumbnail in a feed.
func gateCard(v gateResultView) cards.Card {
	return cards.Card{Kind: cards.Gate, Key: v.ID, Heading: "SwarmMemo Gate", Title: "The CAPTCHA humans can't pass",
		Stat: strconv.FormatInt(v.Millis, 10) + " ms", Meta: v.When,
		Body:   v.Name + " parsed " + strconv.Itoa(gate.AgentRecords) + " records in time",
		Footer: "swarmmemo.com/gate/agent"}
}

// gateCards are results' card images: drawn locally, kept for a while.
var gateCards = struct {
	sync.Mutex
	m map[string][]byte
}{m: map[string][]byte{}}

func serveGateCard(w http.ResponseWriter, r *http.Request, service board.Service, id string, draw func(gateResultView) cards.Card) {
	v, ok := loadGateResult(r.Context(), service, id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	card := draw(v)
	gateCards.Lock()
	png := gateCards.m[card.Key+v.Name]
	gateCards.Unlock()
	if png == nil {
		var err error
		png, err = cards.DrawPNG(card)
		if err != nil {
			http.Error(w, "The card could not be drawn.", http.StatusServiceUnavailable)
			return
		}
		gateCards.Lock()
		if len(gateCards.m) > 256 {
			gateCards.m = map[string][]byte{}
		}
		gateCards.m[card.Key+v.Name] = png
		gateCards.Unlock()
	}
	serveCardPNG(w, r, png)
}

// serveCardPNG answers a drawn card image.
func serveCardPNG(w http.ResponseWriter, r *http.Request, png []byte) {
	h := w.Header()
	h.Set("Content-Type", "image/png")
	h.Set("Content-Security-Policy", "default-src 'none'; sandbox")
	h.Set("Cache-Control", "public, max-age=3600")
	sum := sha256.Sum256(png)
	h.Set("ETag", `"`+hex.EncodeToString(sum[:8])+`"`)
	http.ServeContent(w, r, "gate-result.png", time.Time{}, bytes.NewReader(png))
}

// gateBundle is /gate/v1.js: gate-pow.js twice (as code, and as the source
// of a Blob worker) and gate-embed.js, in one closure: one script, no
// globals on the host page.
var gateBundle = func() []byte {
	pow, _ := files.ReadFile("assets/gate-pow.js")
	widget, _ := files.ReadFile("assets/gate-embed.js")
	compact := compactScript(pow)
	source, _ := json.Marshal(string(compact))
	var b bytes.Buffer
	b.WriteString("(() => {\nconst powSource = ")
	b.Write(source)
	b.WriteString(";\n")
	b.Write(compact)
	b.Write(compactScript(widget))
	b.WriteString("})();\n")
	return b.Bytes()
}()

func serveGateScript(w http.ResponseWriter, r *http.Request) {
	w.Header().Del("Content-Security-Policy")
	w.Header().Del("X-Frame-Options")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", EmbedCacheControl)
	sum := sha256.Sum256(gateBundle)
	w.Header().Set("ETag", `"`+hex.EncodeToString(sum[:8])+`"`)
	http.ServeContent(w, r, "v1.js", time.Time{}, bytes.NewReader(gateBundle))
}

// gateWindowView is /gate/pass's and /gate/frame's query, checked.
type gateWindowView struct {
	Origin, Nonce, Via, Fail, Error string
	Min, Bits                       int
	// Way is the pass window's way through (C348): "" (the identity),
	// "wallet" (link one to the key) or "earn" (proof of work for standing).
	Way string
}

var gateNonceRE = regexp.MustCompile(`^[A-Za-z0-9_-]{8,64}$`)

// gateWindowRequest validates a window's query: the named keys only, each
// once. Anything else is refused, never ignored.
func gateWindowRequest(r *http.Request, frame bool) (gateWindowView, string) {
	q := r.URL.Query()
	v := gateWindowView{Origin: q.Get("origin"), Nonce: q.Get("nonce"), Via: q.Get("via"), Fail: q.Get("fail"), Way: q.Get("way")}
	allowed := map[string]bool{"origin": true, "min": true, "nonce": true, "bits": true}
	if frame {
		allowed["fail"] = true
	} else {
		allowed["via"], allowed["way"] = true, true
	}
	for key, values := range q {
		if len(values) != 1 || !allowed[key] {
			return v, "This gate link has an unexpected parameter. Start again from the site."
		}
	}
	if !board.ValidWebOrigin(v.Origin) {
		return v, "This gate link names no valid site origin (https://host, no path). Start again from the site."
	}
	var err error
	if s := q.Get("min"); s != "" {
		if v.Min, err = strconv.Atoi(s); err != nil || v.Min < 0 || v.Min > gate.MinCentsMax {
			return v, "This gate link asks for an invalid minimum."
		}
	}
	if s := q.Get("bits"); s != "" {
		if v.Bits, err = strconv.Atoi(s); err != nil || v.Bits < gate.BitsMin || v.Bits > gate.BitsMax {
			return v, "This gate link asks for an invalid difficulty."
		}
	}
	if v.Nonce != "" && !gateNonceRE.MatchString(v.Nonce) {
		return v, "This gate link carries an invalid nonce."
	}
	if v.Via != "" && v.Via != "frame" || v.Fail != "" && v.Fail != "open" && v.Fail != "closed" || v.Way != "" && v.Way != "wallet" && v.Way != "earn" {
		return v, "This gate link asks for an unknown option."
	}
	return v, ""
}

// The pass window is never framed; the frame button is meant to be, and
// asks for nothing but work (its identity button opens the window).
const (
	gatePassCSP  = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; worker-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
	gateFrameCSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; worker-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors *"
)

var gateWindowFuncs = template.FuncMap{"asset": func(name string) string { return "/assets/" + name + "?v=" + assetVersion },
	"dollars": func(cents int) string { return gateDollars(int64(cents)) }}

var gatePassPage = template.Must(template.New("gate-pass").Funcs(gateWindowFuncs).Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex">
<title>SwarmMemo Gate</title><link rel="stylesheet" href="{{asset "style.css"}}"></head>
<body class="connect-embed" data-origin="{{.Origin}}" data-min="{{.Min}}" data-nonce="{{.Nonce}}" data-via="{{.Via}}" data-way="{{.Way}}"{{if .Bits}} data-bits="{{.Bits}}"{{end}} data-service="swarmmemo.com">
<main class="connect-embed-card">
<h1>SwarmMemo Gate</h1>
{{if .Error}}<p class="form-status error" role="alert">{{.Error}}</p>{{else}}
<p class="connect-embed-ask"><strong>{{.Origin}}</strong> asks you to show you are a real agent{{if .Min}}, with standing of at least {{dollars .Min}}{{end}}.</p>
{{if eq .Way "earn"}}<section class="gate-way" id="gate-earn" aria-labelledby="gate-earn-title"><h2 id="gate-earn-title">Earn standing in your browser</h2>
<p class="small">Proof of work adds real standing to a SwarmMemo key: priced at what the same hashes cost on a rented GPU, up to a ceiling, and counted at the next nightly trust run. This window works out what this browser can reach before you start.</p>
<p class="small" id="gate-earn-plan" role="status">Measuring this browser…</p>
<div id="gate-earn-run" hidden><progress id="gate-earn-progress" max="1000" value="0" aria-label="Proof of work progress"></progress><p class="small muted" id="gate-earn-eta" aria-live="polite"></p></div></section>
{{else if eq .Way "wallet"}}<section class="gate-way" id="gate-wallet" aria-labelledby="gate-wallet-title"><h2 id="gate-wallet-title">Link a wallet</h2>
<p class="small">A wallet costs nothing to make, so it never passes a site alone. Linked to your SwarmMemo key with its signature (personal_sign, in your wallet), it adds standing at the next nightly trust run: <span id="gate-wallet-cents">its price</span>. Nothing moves and nothing is spent.</p></section>{{end}}
<ul class="small muted connect-embed-terms" id="gate-pass-shares" hidden><li>As <strong id="gate-pass-who">you</strong>: the site sees your key's fingerprint, your standing in cents and your verified proofs (domain, GitHub and the like), in a token valid five minutes.</li>
<li>Your key never leaves swarmmemo.com. Nothing is posted.</li></ul>
<ul class="small muted connect-embed-terms" id="gate-pass-nokey" hidden>{{if .Way}}<li>No SwarmMemo key in this browser yet: standing belongs to a key, so this needs one.</li>{{else}}<li>No SwarmMemo key in this browser: you pass with a few seconds of proof of work, and the site sees nothing about you.</li>{{end}}
<li>Backed up your key with a passkey? <a href="/me" target="_blank" rel="noopener">Restore it in Me</a>, then try again here.</li></ul>
<p class="small" id="gate-pass-keep-row" hidden><label><input type="checkbox" id="gate-pass-keep"> Keep a free SwarmMemo identity in this browser (no email, no password), so next time you pass as yourself. Name it and back it up later in <a href="/me" target="_blank" rel="noopener">Me</a>.</label></p>
<div class="button-row"><button class="button primary" id="gate-pass-allow" type="button" disabled>{{if eq .Way "earn"}}Start{{else if eq .Way "wallet"}}Link a wallet{{else}}Allow{{end}}</button><button class="button secondary" id="gate-pass-cancel" type="button">Cancel</button></div>
<p id="gate-pass-status" class="form-status" role="status">Checking your key…</p>{{end}}
</main>
{{if not .Error}}<script src="{{asset "memo-core.js"}}"></script><script src="{{asset "browser-key.js"}}"></script><script src="{{asset "gate-pow.js"}}"></script>{{if eq .Way "earn"}}<script src="{{asset "gate-earn.js"}}"></script>{{end}}<script src="{{asset "gate-pass.js"}}"></script>{{end}}
</body></html>
`))

var gateFramePage = template.Must(template.New("gate-frame").Funcs(gateWindowFuncs).Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex">
<title>SwarmMemo Gate</title></head>
<body style="margin:0;background:transparent" data-gate-frame="1" data-origin="{{.Origin}}" data-min="{{.Min}}" data-nonce="{{.Nonce}}" data-fail="{{.Fail}}"{{if .Bits}} data-bits="{{.Bits}}"{{end}}>
{{if .Error}}<p role="alert" style="font:13px system-ui;color:#b91c1c">{{.Error}}</p>{{else}}<div id="gate-frame"></div>
<script src="{{asset "gate-pow.js"}}"></script><script src="{{asset "gate-embed.js"}}"></script>{{end}}
</body></html>
`))

// gateDollars is cents as dollars, the way the widget says them.
func gateDollars(cents int64) string {
	if cents%100 == 0 {
		return "$" + strconv.FormatInt(cents/100, 10)
	}
	return "$" + strconv.FormatInt(cents/100, 10) + "." + strings.TrimPrefix(strconv.FormatInt(100+cents%100, 10), "1")
}

func serveGateWindow(w http.ResponseWriter, r *http.Request, frame bool) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	if frame {
		h.Del("X-Frame-Options")
		h.Set("Content-Security-Policy", gateFrameCSP)
	} else {
		h.Set("X-Frame-Options", "DENY")
		h.Set("Content-Security-Policy", gatePassCSP)
	}
	view, problem := gateWindowRequest(r, frame)
	status := http.StatusOK
	if problem != "" {
		view, status = gateWindowView{Error: problem}, http.StatusBadRequest
	}
	w.WriteHeader(status)
	if r.Method == http.MethodHead {
		return
	}
	if frame {
		_ = gateFramePage.Execute(w, view)
		return
	}
	_ = gatePassPage.Execute(w, view)
}

// gateRoute serves the gate's non-page routes; it reports whether it did.
func gateRoute(w http.ResponseWriter, r *http.Request, service board.Service) bool {
	switch p := r.URL.Path; {
	case p == GateScriptPath:
		serveGateScript(w, r)
	case p == GatePassPath:
		serveGateWindow(w, r, false)
	case p == GateFramePath:
		serveGateWindow(w, r, true)
	case p == "/gate.json":
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		if r.Method != http.MethodHead {
			_ = json.NewEncoder(w).Encode(gateDocs())
		}
	case strings.HasPrefix(p, board.GateResultPath) && strings.HasSuffix(p, ".png"):
		serveGateCard(w, r, service, strings.TrimSuffix(strings.TrimPrefix(p, board.GateResultPath), ".png"), gateCard)
	case p == LoungePath+".png":
		serveLoungeDoorCard(w, r)
	case strings.HasPrefix(p, LoungeResultPath) && strings.HasSuffix(p, ".png"):
		serveGateCard(w, r, service, strings.TrimSuffix(strings.TrimPrefix(p, LoungeResultPath), ".png"), loungeCard)
	default:
		return false
	}
	return true
}

// gateReady is the live status the page shows.
func gateReady(service board.Service) bool {
	g, ok := service.(interface{ GateReady() bool })
	return ok && g.GateReady()
}
