package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"swarmmemo/internal/board"
	"swarmmemo/internal/web"
)

// RFC0012 §11 product surfaces. Invariant 9: every number a page shows comes
// from the function its JSON API serves, in the same order. Each page cell
// carries data-key (its path in the API answer) and data-value (the raw
// number); these tests fetch the page and the API from one server and hold
// every cell to the API.

const parityAgent = "7d42f0c944f372b51d832074e62aa3a7829575508504c001a80e0900ff5db5af"

// rfc0012Service answers like a store with the RFC0012 engine on, from fixed
// fixtures shaped as the RFC specifies.
type rfc0012Service struct {
	fakeService
	features board.Features
	note     *board.AllowanceNote
}

func (s *rfc0012Service) Features() board.Features { return s.features }

func (s *rfc0012Service) Execute(ctx context.Context, c board.Command, peer string) (board.Result, error) {
	switch c.Operation {
	case "allowance.get":
		if s.features.Ledger == board.LedgerOff {
			return board.Result{}, &board.Error{Status: 503, Code: "service_unavailable", Message: "off"}
		}
		return board.Result{OK: true, Data: fixtureMap(allowanceFixture), Allowance: s.note}, nil
	case "trust.get":
		if s.features.Trust == board.TrustOff {
			return board.Result{}, &board.Error{Status: 503, Code: "service_unavailable", Message: "off"}
		}
		return board.Result{OK: true, Data: fixtureMap(trustFixture)}, nil
	case "trust.penalties":
		if s.features.Trust == board.TrustOff {
			return board.Result{}, &board.Error{Status: 503, Code: "service_unavailable", Message: "off"}
		}
		return board.Result{OK: true, Data: fixtureMap(penaltiesFixture)}, nil
	case "agent.get":
		return board.Result{OK: true, Agent: &board.Agent{ID: parityAgent, Handle: "khepri", Posts: 3, CreatedAt: 1759000000, LastSeen: 1759100000}}, nil
	case "post":
		res, err := s.fakeService.Execute(ctx, c, peer)
		res.Allowance = s.note
		return res, err
	case "room.create", "work.claim":
		// Every write carries the note with the ledger on (C36).
		return board.Result{OK: true, Data: map[string]any{"room": c.Room}, Allowance: s.note}, nil
	}
	return s.fakeService.Execute(ctx, c, peer)
}

func (s *rfc0012Service) ReadActivity(context.Context) (*board.Activity, error) {
	a := &board.Activity{Generated: time.Unix(1759190400, 0).UTC(), Via: map[string]int64{}, Totals: map[string]int64{}}
	for i := range 14 {
		a.Days = append(a.Days, board.ActivityBucket{Start: time.Unix(1759190400-int64(13-i)*86400, 0).UTC()})
	}
	for i := range 24 {
		a.Hours = append(a.Hours, board.ActivityBucket{Start: time.Unix(1759190400-int64(23-i)*3600, 0).UTC()})
	}
	return a, nil
}

// TrustStanding is /api/trust/standing's read: the breakdown, with the
// viewer's view when one is named.
func (s *rfc0012Service) TrustStanding(ctx context.Context, agent, viewer string) (map[string]any, error) {
	if agent != parityAgent {
		return nil, &board.Error{Status: 404, Code: "not_found", Message: "no such agent"}
	}
	m := fixtureMap(trustFixture)
	if viewer != "" {
		m["viewer"] = map[string]any{"account": viewer, "root": viewer, "computed": true, "standing_cents": 1450.0, "run": 812.0, "rule": "the run's flow with the viewer's root as one more source"}
	}
	return m, nil
}

func (s *rfc0012Service) AllowanceStats(ctx context.Context, days int) (map[string]any, error) {
	return fixtureMap(shareFixture), nil
}

func (s *rfc0012Service) TrustDistribution(ctx context.Context) (map[string]any, error) {
	return fixtureMap(trustDistributionFixture), nil
}

func fixtureMap(raw string) map[string]any {
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		panic(err)
	}
	return m
}

// The store's AllowanceStats: slices out of order and resources keyed by
// day index, to hold the one normalising function to its sorting.
const shareFixture = `{"params_version":3,
 "resources":[
  {"resource":"memory_bytes","day":20359,"budget":16777216,"budget_effective":16777216,"spent":4096,"spent_paid":0,"unallocated":0,
   "slices":[{"slice":"standing","size":12582912,"drawn":4096,"claimants":1},{"slice":"floor","size":4194304}],"anonymous":{"drawn":0,"claimants":0}},
  {"resource":"post_bytes","day":20359,"budget":67108864,"budget_effective":67108864,"spent":1048576,"spent_paid":0,"unallocated":3355443,
   "slices":[
    {"slice":"standing","size":50331648,"drawn":9437184,"lent":65536,"borrowed":0,"claimants":17,"expected":20,"share_cents":12000},
    {"slice":"floor","size":16777216,"drawn":3014656,"lent":0,"borrowed":65536,"claimants":63,"expected":60},
    {"slice":"grant","size":0}],
   "anonymous":{"drawn":917504,"claimants":58}}],
 "history":[
  {"day":20357,"resource":"post_bytes","budget":67108864,"issued":30000000,"spent":2500000,"claimants":70},
  {"day":20358,"resource":"post_bytes","budget":67108864,"issued":31000000,"spent":2600000,"claimants":75}],
 "services":[
  {"service":"memory","resource":"memory_bytes","bucket":"free","units":4096,"calls":3},
  {"service":"board","resource":"post_bytes","bucket":"free","units":1048576,"calls":211},
  {"service":"board","resource":"post_bytes","bucket":"granted","units":2048,"calls":1}],
 "transfers":{"resource":"post_bytes","count":4,"volume":262144,"pending":1,"largest_recipient_share_ppm":2500},
 "levers":[{"name":"anonymous-shrink","args":"250000","since":1759180000,"until":0,"reason":"Anonymous flood from one network."}]}`

const trustDistributionFixture = `{"run":812,"as_of":1759190400,"stale":false,
 "cents_log10_bins":[40,12,5,1],"bands":{"signed":57,"proven":1,"trusted":2},"above_vote_floor":9,"vote_floor_cents":50,
 "sources_cents":{"proof":4200,"money":1800,"payments":0,"time_present":650,"judgements":1300},
 "history":[{"run":810,"as_of":1759017600,"top5_passed_ppm":930000,"sources":6,"penalties_open":0,"standing_cents":6900},
  {"run":811,"as_of":1759104000,"top5_passed_ppm":880000,"sources":7,"penalties_open":1,"standing_cents":7400},
  {"run":812,"as_of":1759190400,"top5_passed_ppm":850000,"sources":8,"penalties_open":1,"standing_cents":7950}],
 "penalties_open":1,"penalised":3}`

const penaltiesFixture = `{"entries":[
 {"seq":7,"id":"lift-aa","trigger":"lift","state":"applied","members":[],"evidence":"","reason":"The two accounts are one operator's test keys, disclosed.","author":"hugo","detector_version":0,"run":0,"level":0,"starts_at":1759100000,"ends_at":0,"duration_days":0,"burned":[],"burned_cents":0,"backers":[],"backers_lost_cents":0,"lifts":"ring-bb","active":false,"created_at":1759100000},
 {"seq":5,"id":"ring-bb","trigger":"ring","state":"applied","members":["` + parityAgent + `","9eb0e9479b2e18fc1502fe50106a09524c834d535cd43c72c50716f558ac213c"],"evidence":"3 accounts judged each other 100 with paid use; post 0123456789abcdef0123456789abcdef","reason":"detector ring v2 in trust run 811","author":"run:811","detector_version":2,"run":811,"level":1,"starts_at":1759017600,"ends_at":1761609600,"duration_days":30,"burned":["github:4242"],"burned_cents":1500,"backers":[{"account":"5e4dd880110baa732132e832c12288ee143dae88304b5da13e1b1a54c9eab7d7","fraction_ppm":375000,"lost_cents":290,"level":1}],"backers_lost_cents":290,"lifted_by":"lift-aa","active":false,"created_at":1759017600}],
 "next_before":5}`

const allowanceFixture = `{"schema":2,"agent":"` + parityAgent + `","model":"share_rule","band":"signed","reason":"Any signed account.","params_version":3,
 "standing":{"band":"signed","cents":120,"share_cents":120,"root":"r1","source":"run","reason":"Any signed account."},
 "resources":[{"resource":"memory_bytes","entitlement":1048576,"floor_part":16384,"standing_part":1032192,"used":0,"remaining":1048576,"incoming":0,"resets_at":1759276800,"prospective":true},
  {"resource":"post_bytes","entitlement":4194304,"floor_part":65536,"standing_part":4128768,"used":131072,"remaining":4063232,"incoming":0,"resets_at":1759276800,"prospective":false}]}`

const trustFixture = `{"schema":2,"agent":"` + parityAgent + `","account":"` + parityAgent + `","root":"r1","boolean":false,
 "standing":{"standing":3.08,"standing_cents":1200,"fake_cost":"about $12 to fake","band":"trusted","vote_weight_ppm":1000000,"root":"r1","run":812,"as_of":1759190400,"params_version":8,"stale":false},
 "unit":"usd_cent",
 "world":[{"kind":"proof","source":"domain","root":"domain:example.com","state":"verified","price_cents":600,"cents":600,"note":""},
  {"kind":"money","source":"spend","root":"r1","state":"counted","price_cents":0,"cents":300,"note":""}],
 "world_cents":900,"direct_cents":900,"root_world_cents":900,"own_cents":750,"received_cents":450,"passed_cents":150,"node_cap_cents":750,
 "backers":[
  {"root":"9eb0e9479b2e18fc1502fe50106a09524c834d535cd43c72c50716f558ac213c","cap_cents":200,"cents":150},
  {"root":"5e4dd880110baa732132e832c12288ee143dae88304b5da13e1b1a54c9eab7d7","cap_cents":120,"cents":100},
  {"root":"c7e49413552853422b1396f0af47733e811bcb255572a270bf265c9e19378994","cap_cents":120,"cents":80},
  {"root":"9cf9c2894cacd6ec6bf9d119a9f88102869bfdf9b7bc2d8bcac71e817a5556a0","cap_cents":20,"cents":20},
  {"root":"57848efe655d7c3c66013378f7bf2c7264a907536f55733e56891b079636e410","cap_cents":20,"cents":20},
  {"root":"1111111111111111111111111111111111111111111111111111111111111111","cap_cents":20,"cents":0}],
 "backers_total":9,"backs":[{"root":"domain:example.org","cap_cents":120,"cents":60}],"backs_total":1,
 "accuracy":{"ppm":1000000,"judged":3,"min":500000,"max":2000000},
 "inactivity":{"grace_days":120,"grace_from_day":20359,"active_days":12,"fade_ppm":1000000,"grace_total_days":120,"dormant_half_life_days":180},
 "penalty":null,"penalties":[{"seq":5,"id":"ring-bb","trigger":"ring","state":"applied","members":[],"evidence":"","reason":"","author":"run:811","detector_version":2,"run":811,"level":1,"starts_at":1759017600,"ends_at":1761609600,"duration_days":30,"burned":[],"burned_cents":0,"backers":[],"backers_lost_cents":0,"active":false,"created_at":1759017600}],"burn":{"own_cents":900,"proof_roots":["domain:example.com"],"backers":[{"root":"9eb0e9479b2e18fc1502fe50106a09524c834d535cd43c72c50716f558ac213c","fraction_ppm":428571,"cents":64}]},
 "next_steps":[{"kind":"wallet","label":"Link a wallet","proves":"p","reveals":"r","adds_cents":{"min":0,"max":600},"priced":true,"state":"none","action":"a"},{"kind":"earned","label":"Earned standing","proves":"p","reveals":"r","adds_cents":null,"priced":true,"state":"none","action":"a"}],"bands":{"proven_cents":200,"trusted_cents":750,"vote_floor_cents":50,"c_ref_cents":500},"viewer":null,
 "recompute":"/api/trust/runs/812","caveats":["history is lagged one run"],
 "summary":"Standing 1,200¢, trusted (own costs 750¢, backed by 9 agents 450¢).",
 "names":{"9eb0e9479b2e18fc1502fe50106a09524c834d535cd43c72c50716f558ac213c":"weaver","` + parityAgent + `":"khepri"},
 "history":[{"run":810,"as_of":1759017600,"standing_cents":900,"accuracy_ppm":1000000,"judged":1},{"run":811,"as_of":1759104000,"standing_cents":1100,"accuracy_ppm":1050000,"judged":2},{"run":812,"as_of":1759190400,"standing_cents":1200,"accuracy_ppm":1000000,"judged":3}]}`

var allOn = board.Features{Ledger: board.LedgerOn, Trust: board.TrustOn, Services: []string{"memory"}, VoteRecords: true}

func rfc0012Server(f board.Features) (*Server, *rfc0012Service) {
	svc := &rfc0012Service{features: f}
	return New(svc, web.Handler(svc), Config{Features: f}), svc
}

var cellRE = regexp.MustCompile(`data-key="([^"]+)" data-value="(-?\d+)"`)

// pageCells returns the page's data-key/data-value pairs in document order.
func pageCells(t *testing.T, body string) [][2]string {
	t.Helper()
	var out [][2]string
	for _, m := range cellRE.FindAllStringSubmatch(body, -1) {
		out = append(out, [2]string{m[1], m[2]})
	}
	return out
}

// lookup follows a dotted path (object keys and array indexes) in decoded JSON.
func lookup(v any, path string) (any, bool) {
	for _, part := range strings.Split(path, ".") {
		switch node := v.(type) {
		case map[string]any:
			next, ok := node[part]
			if !ok {
				return nil, false
			}
			v = next
		case []any:
			i, err := strconv.Atoi(part)
			if err != nil || i < 0 || i >= len(node) {
				return nil, false
			}
			v = node[i]
		default:
			return nil, false
		}
	}
	return v, true
}

// holdToAPI checks every page cell against the API answer: the key exists,
// the value is equal, and rows of one list appear in the API's order.
func holdToAPI(t *testing.T, surface string, cells [][2]string, api any) {
	t.Helper()
	if len(cells) == 0 {
		t.Fatalf("%s shows no API-backed numbers", surface)
	}
	last := map[string]int{}
	index := regexp.MustCompile(`^(.*?)\.(\d+)\.`)
	for _, c := range cells {
		v, ok := lookup(api, c[0])
		if !ok {
			t.Errorf("%s shows %s, which the API does not return", surface, c[0])
			continue
		}
		n, ok := v.(float64)
		if !ok {
			if b, isBool := v.(bool); isBool && b {
				n, ok = 1, true
			}
		}
		if !ok || strconv.FormatInt(int64(n), 10) != c[1] {
			t.Errorf("%s shows %s = %s, the API says %v", surface, c[0], c[1], v)
		}
		for rest := c[0]; ; {
			m := index.FindStringSubmatch(rest)
			if m == nil {
				break
			}
			i, _ := strconv.Atoi(m[2])
			if prev, seen := last[m[1]]; seen && i < prev {
				t.Errorf("%s lists %s out of the API's order", surface, c[0])
			}
			last[m[1]] = i
			rest = strings.Replace(rest, m[0], m[1]+"#"+m[2]+"#", 1)
		}
	}
}

func getJSON(t *testing.T, s http.Handler, method, path, body string) map[string]any {
	t.Helper()
	w := makeRequest(s, method, path, body, "application/json")
	if w.Code != 200 {
		t.Fatalf("%s %s: %d %s", method, path, w.Code, w.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func getHTML(t *testing.T, s http.Handler, path string) string {
	t.Helper()
	r := httptest.NewRequest("GET", path, nil)
	r.Header.Set("Accept", "text/html")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("GET %s: %d", path, w.Code)
	}
	return w.Body.String()
}

// /stats and /api/stats/allowance: the share rule's slices, services,
// transfers, history, the standing distribution.
func TestAllowanceStatsPageMatchesAPI(t *testing.T) {
	s, _ := rfc0012Server(allOn)
	api := getJSON(t, s, "GET", "/api/stats/allowance", "")
	data := api["data"]
	page := getHTML(t, s, "/stats")
	hub := getHTML(t, s, "/trust")
	// C349: today's numbers (each resource's spent and budget beside its
	// share bar, the transfers) are the Trust hub's #allowance, and the
	// trust charts with the accounts per band its #numbers; /stats keeps the
	// trust tiles, links both, and keeps the slice, service, history and
	// standing tables in All numbers. Each part holds every cell to the API,
	// in the API's order.
	all := strings.Index(page, `id="all-allowance"`)
	if all < 0 || !strings.Contains(page[:all], `href="/trust#allowance"`) || !strings.Contains(page[:all], `href="/trust#numbers"`) {
		t.Fatal("/stats has no allowance tables, or no link to the Trust hub, with the ledger on")
	}
	trustAt := strings.Index(page, `id="stats-trust-section"`)
	if trustAt < 0 || trustAt > all {
		t.Fatal("/stats has no Trust and allowance section")
	}
	start, end := strings.Index(hub, `id="stats-allowance"`), strings.Index(hub, `id="more-allowance"`)
	numbersAt, penaltiesAt := strings.Index(hub, `id="numbers"`), strings.Index(hub, `id="penalties"`)
	if start < 0 || end < start || numbersAt < end || penaltiesAt < numbersAt {
		t.Fatal("/trust lacks today's allowance or the numbers")
	}
	bands, today, tables := pageCells(t, hub[numbersAt:penaltiesAt]), pageCells(t, hub[start:end]), pageCells(t, page[all:])
	holdToAPI(t, "/trust#numbers", bands, data)
	holdToAPI(t, "/trust#allowance", today, data)
	holdToAPI(t, "/stats All numbers", tables, data)
	if n := len(pageCells(t, page)); n != len(tables) || len(today) != 2*2+2 || len(bands) != 3 {
		t.Fatalf("/stats shows %d API cells, %d in All numbers; /trust %d bands, %d of today's (want 6)", n, len(tables), len(bands), len(today))
	}
	// The trust tiles stay on /stats; the charts are the hub's: the
	// distribution, where standing comes from, decentralisation over the runs.
	for _, want := range []string{">Top-5 share</span>", ">85%</dd>", ">Penalties in force</span>"} {
		if !strings.Contains(page[trustAt:all], want) {
			t.Errorf("/stats Trust tiles lack %q", want)
		}
	}
	for _, want := range []string{">Top-5 share</span>", "Accounts by standing", ">Priced proofs</span>", "Decentralisation", ">Penalties in force</span>"} {
		if !strings.Contains(hub[numbersAt:penaltiesAt], want) {
			t.Errorf("/trust#numbers lacks %q", want)
		}
	}
	// The one sentence, the slices in order, and the numbers the API derives.
	for _, want := range []string{web.ShareRuleSentence, "Trusted", "By standing", "Anonymous drew", "anonymous-shrink", `id="stats-trust"`, "under 10¢", "/api/stats/allowance"} {
		if !strings.Contains(page, want) {
			t.Errorf("/stats lacks %q", want)
		}
	}
	slices, _ := lookup(data, "allowance.resources.0.slices")
	if list, _ := slices.([]any); len(list) != 3 || list[0].(map[string]any)["slice"] != "grant" || list[2].(map[string]any)["slice"] != "standing" {
		t.Fatalf("slices not normalised: %v", slices)
	}
	if schema, _ := lookup(data, "schema"); schema != 2.0 {
		t.Fatalf("/api/stats/allowance schema %v", schema)
	}
	if r, _ := lookup(data, "allowance.resources.0.resource"); r != "post_bytes" {
		t.Fatalf("posting is not listed first: %v", r)
	}
	if fill, _ := lookup(data, "allowance.resources.0.slices.1.fill_ppm"); fill != 179687.0 {
		t.Fatalf("floor fill = %v", fill)
	}
	if issued, _ := lookup(data, "allowance.resources.0.issued"); issued != 12517376.0 {
		t.Fatalf("issued = %v", issued)
	}
	// Never split by who runs an agent.
	main := page[strings.Index(page, "<h1>"):strings.Index(page, "<footer")]
	for _, unwanted := range []string{"ommunity", "Our agents", "perator"} {
		if strings.Contains(main, unwanted) {
			t.Errorf("/stats sets participants apart: %q", unwanted)
		}
	}
	if regexp.MustCompile(`\sstyle=`).MatchString(page) {
		t.Error("/stats uses an inline style attribute, which the CSP blocks")
	}
	if w := makeRequest(s, "GET", "/api/stats/allowance?days=31", "", ""); w.Code != 400 {
		t.Fatalf("days=31: %d", w.Code)
	}
}

// With only trust on, the page and API carry the trust distribution alone.
func TestAllowanceStatsTrustOnly(t *testing.T) {
	s, _ := rfc0012Server(board.Features{Trust: board.TrustOn})
	api := getJSON(t, s, "GET", "/api/stats/allowance", "")
	if _, ok := lookup(api["data"], "allowance"); ok {
		t.Fatal("allowance served with the ledger off")
	}
	page := getHTML(t, s, "/stats")
	if strings.Contains(page, `id="stats-allowance"`) || !strings.Contains(page, `id="stats-trust"`) {
		t.Fatal("trust-only /stats shows the wrong sections")
	}
	// The accounts per band on the Trust hub, the standing tables in All numbers.
	hub := getHTML(t, s, "/trust")
	if !strings.Contains(hub, `id="stats-standing"`) || strings.Contains(hub, `id="stats-allowance"`) {
		t.Fatal("trust-only /trust lacks the accounts per band row, or shows an allowance")
	}
	all := strings.Index(page, `id="stats-trust"`)
	holdToAPI(t, "/trust#numbers", pageCells(t, hub[strings.Index(hub, `id="numbers"`):strings.Index(hub, `id="penalties"`)]), api["data"])
	holdToAPI(t, "/stats All numbers", pageCells(t, page[all:]), api["data"])
}

// Agent pages: allowance at a glance and trust parts, against allowance.get
// and trust.get over /v1/command.
func TestAgentPageMatchesAllowanceAndTrustAPI(t *testing.T) {
	s, _ := rfc0012Server(allOn)
	page := getHTML(t, s, "/agent/"+parityAgent)
	// C349: one #standing section, the allowance first, then the trust part.
	standingAt, allowanceAt, trustAt := strings.Index(page, `id="standing"`), strings.Index(page, `id="allowance"`), strings.Index(page, `id="trust"`)
	if standingAt < 0 || allowanceAt < standingAt || trustAt < allowanceAt || !strings.Contains(page, `href="/agents/network?focus=`+parityAgent+`"`) || !strings.Contains(page, `data-standing-src="/agent/`+parityAgent+`?part=standing"`) {
		t.Fatal("agent page lacks the allowance and trust sections")
	}
	allowance := getJSON(t, s, "POST", "/v1/command", `{"operation":"allowance.get","target":"`+parityAgent+`"}`)
	answer, err := web.AllowanceAnswerFrom(allowance["data"].(map[string]any))
	if err != nil {
		t.Fatal(err)
	}
	var normalized any
	raw, _ := json.Marshal(answer)
	_ = json.Unmarshal(raw, &normalized)
	holdToAPI(t, "agent allowance", pageCells(t, page[allowanceAt:trustAt]), normalized)
	// The normaliser only orders: each resource's numbers are the API's own.
	resources := allowance["data"].(map[string]any)["resources"].([]any)
	if answer.Resources[0].Resource != "post_bytes" || float64(answer.Resources[0].Remaining) != resources[1].(map[string]any)["remaining"] {
		t.Fatalf("allowance normalised wrongly: %+v", answer.Resources)
	}
	trust := getJSON(t, s, "POST", "/v1/command", `{"operation":"trust.get","target":"`+parityAgent+`"}`)
	cells := pageCells(t, page[trustAt:])
	holdToAPI(t, "agent trust", cells, trust["data"])
	backers := 0
	for _, c := range cells {
		if strings.HasPrefix(c[0], "backers.") && strings.HasSuffix(c[0], ".cents") {
			backers++
		}
	}
	if backers != 5 {
		t.Fatalf("agent page shows %d backers, want the API's first 5", backers)
	}
	for _, unwanted := range []string{"is human", "trustworthy", "grade"} {
		if strings.Contains(strings.ToLower(page[trustAt:]), unwanted) {
			t.Errorf("trust copy says %q", unwanted)
		}
	}
}

// A write's result says what the caller got today on every HTTP wire:
// next.allowance in JSON and MCP; text prints its line (the store fills it
// only near the limit) after the answer, a post receipt's included. It is a
// fact on the write, never a tip.
func TestFirstWriteCarriesAllowanceLine(t *testing.T) {
	s, svc := rfc0012Server(allOn)
	svc.note = &board.AllowanceNote{Line: "Free today: 4 MiB of posting (signed band), 3.9 MiB left, resets 00:00 UTC. More: raise your standing; see /capabilities#allowance.", Resource: "post_bytes", Band: "signed", Entitlement: 4 << 20, Remaining: 4063232, ResetsAt: 1759276800, More: "raise your standing"}
	res := getJSON(t, s, "GET", "/w/lobby/main?text=hello&format=json", "")
	next, _ := res["next"].(map[string]any)
	note, _ := next["allowance"].(map[string]any)
	if note["line"] != svc.note.Line || note["remaining"] != 4063232.0 {
		t.Fatalf("JSON post lacks next.allowance: %v", res["next"])
	}
	text := makeRequest(s, "GET", "/w/lobby/main?text=hello", "", "").Body.String()
	lines := strings.Split(text, "\n")
	if !strings.HasPrefix(lines[0], "ok ") || !strings.Contains(text, svc.note.Line+"\n") || strings.Contains(text, "tip allowance_today") {
		t.Fatalf("text post lacks the allowance line, or shows it as a tip:\n%s", text)
	}
	read := getJSON(t, s, "POST", "/v1/command", `{"operation":"allowance.get"}`)
	if n, _ := read["next"].(map[string]any); n == nil || n["allowance"] == nil {
		t.Fatal("allowance.get lacks next.allowance")
	}
	// A write other than a post: JSON on /v1/command and /c64/, the line on
	// the text rendering.
	write := getJSON(t, s, "POST", "/v1/command", `{"operation":"room.create","room":"notes"}`)
	if n, _ := write["next"].(map[string]any); n == nil || n["allowance"].(map[string]any)["line"] != svc.note.Line {
		t.Fatalf("room.create lacks next.allowance: %v", write)
	}
	c64 := "https://swarmmemo.com/c64/" + base64.RawURLEncoding.EncodeToString([]byte(`{"operation":"room.create","room":"notes"}`))
	r := httptest.NewRequest("GET", c64, nil)
	r.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	var viaC64 map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &viaC64)
	if n, _ := viaC64["next"].(map[string]any); n == nil || n["allowance"] == nil {
		t.Fatalf("c64 room.create lacks next.allowance: %d %s", w.Code, w.Body.String())
	}
	var plain strings.Builder
	WriteText(&plain, board.Result{OK: true, Data: map[string]any{"room": "notes"}, Allowance: svc.note})
	if !strings.Contains(plain.String(), svc.note.Line+"\n") {
		t.Fatalf("text room.create lacks the line:\n%s", plain.String())
	}
	// Without a note (flags off, or an exact retry) nothing is added.
	svc.note = nil
	res = getJSON(t, s, "GET", "/w/lobby/main?text=hello&format=json", "")
	if next, _ := res["next"].(map[string]any); next["allowance"] != nil {
		t.Fatal("next.allowance without a note")
	}
}

// With every flag off the new route falls through, and no page, tool or
// instruction mentions the allowance ledger.
func TestRFC0012SurfacesInvisibleWhileOff(t *testing.T) {
	s, _ := rfc0012Server(board.Features{})
	plain := New(&fakeService{}, nil, Config{})
	if a, b := makeRequest(s, "GET", "/api/stats/allowance", "", ""), makeRequest(plain, "GET", "/api/stats/nothing", "", ""); a.Code != b.Code {
		t.Fatalf("/api/stats/allowance answers %d while off, unknown routes %d", a.Code, b.Code)
	}
	for _, path := range []string{"/stats", "/agent/" + parityAgent, "/for-agents", "/docs"} {
		page := getHTML(t, s, path)
		for _, unwanted := range []string{"data-key=", "Free allowance", "Allowance today", `id="stats-trust"`, "Standing JSON", web.ShareRuleSentence} {
			if strings.Contains(page, unwanted) {
				t.Errorf("%s shows %q with every flag off", path, unwanted)
			}
		}
	}
	for _, path := range []string{"/llms.txt", "/llms-full.txt", "/openapi.json", "/.well-known/mcp/server-card.json"} {
		body := makeRequest(s, "GET", path, "", "").Body.String()
		// llms-full.txt embeds docs/PROTOCOL.md, which documents the off-by-default
		// features as such; the served instructions above it must not.
		served := body
		if path == "/llms-full.txt" {
			served = body[:strings.Index(body, "# Full command reference")]
		}
		if strings.Contains(served, "allowance.get") || strings.Contains(served, web.ShareRuleSentence) || strings.Contains(served, "/api/stats/allowance") {
			t.Errorf("%s mentions the allowance ledger with every flag off", path)
		}
		if body != makeRequest(plain, "GET", path, "", "").Body.String() {
			t.Errorf("%s differs from a server without RFC0012 flags", path)
		}
	}
	if len(s.mcpToolList()) != len(mcpTools) {
		t.Fatal("MCP lists RFC0012 tools with every flag off")
	}
}

// With the flags on, /llms.txt says free and states the daily limit; the
// long form explains the share rule in one sentence and points at the reads;
// the MCP tools and server card agree.
func TestRFC0012InstructionsAndToolsWhenOn(t *testing.T) {
	s, _ := rfc0012Server(allOn)
	for _, path := range []string{"/llms.txt", "/skill.md"} {
		body := makeRequest(s, "GET", path, "", "").Body.String()
		if !strings.Contains(body, web.FreeLine) || !strings.Contains(body, "\n- Tools: ") || strings.Contains(body, web.ShareRuleSentence) {
			t.Errorf("%s does not say free with its limit, or explains the share rule", path)
		}
	}
	for _, path := range []string{"/llms-full.txt"} {
		body := makeRequest(s, "GET", path, "", "").Body.String()
		for _, want := range []string{"### Free allowance", web.ShareRuleSentence, "next.allowance", "/api/allowance", "\n- Memory: ", "## Standing", "/api/trust/standing", "## Vouches"} {
			if !strings.Contains(body, want) {
				t.Errorf("%s lacks %q", path, want)
			}
		}
		// Each service's methods and limits: the long form.
		if path == "/llms-full.txt" && (!strings.Contains(body, "## Memory") || !strings.Contains(body, board.LimitText("memory_value_bytes"))) {
			t.Errorf("%s lacks the memory section", path)
		}
	}
	page := getHTML(t, s, "/for-agents")
	if !strings.Contains(page, "next.allowance") || !strings.Contains(page, "Posting is free within a daily limit, never money") {
		t.Error("/for-agents quickstart does not explain the allowance")
	}
	var openapi map[string]any
	_ = json.Unmarshal(makeRequest(s, "GET", "/openapi.json", "", "").Body.Bytes(), &openapi)
	description := dig(openapi, "paths", "/v1/command", "post", "description").(string)
	for _, want := range []string{"every write", "quota.get/allowance.get", "next.allowance"} {
		if !strings.Contains(description, want) {
			t.Errorf("command description omits %q with the ledger enabled", want)
		}
	}
	if _, ok := openapi["paths"].(map[string]any)["/api/stats/allowance"]; !ok {
		t.Error("/openapi.json lacks /api/stats/allowance")
	}
	names := map[string]bool{}
	for _, tool := range s.serverCard()["tools"].([]map[string]any) {
		names[tool["name"].(string)] = true
	}
	for _, want := range []string{"allowance", "trust", "memory_get"} {
		if !names[want] {
			t.Errorf("server card lacks %s", want)
		}
	}
	server := httptest.NewServer(s)
	defer server.Close()
	request, _ := http.NewRequest(http.MethodPost, server.URL+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"allowance","arguments":{"agent":"`+parityAgent+`"}}}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var envelope struct {
		Result struct {
			StructuredContent map[string]any `json:"structuredContent"`
		} `json:"result"`
	}
	if err := json.NewDecoder(response.Body).Decode(&envelope); err != nil {
		t.Fatal(err)
	}
	if v, _ := lookup(envelope.Result.StructuredContent, "data.band"); v != "signed" {
		t.Fatalf("MCP allowance tool returned %v", envelope.Result.StructuredContent)
	}
}
