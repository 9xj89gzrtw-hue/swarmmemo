package board

// The public trust network (/api/trust/graph, the network on /trust and
// /agents/network): identities sized by standing in the latest trust run, and
// the public edges standing moves along (docs/TRUST_MODEL.md, "The graph
// stays"): vouches, accepted work, verified witnesses, and verified key links
// between accounts. Votes, replies, DMs and anything private are never edges
// here. Only public accounts (publicAccountSQL) are named, as in trust.get
// and the run snapshot. The graph is capped: the top accounts by standing
// (the core), then their neighbours up to a node cap, and the heaviest edges
// up to an edge cap.

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"sync"

	"swarmmemo/internal/allowance"
	"swarmmemo/internal/trust"
)

const (
	// TrustGraphCoreDefault and TrustGraphCoreMax bound the core: accounts
	// with standing, highest first (?limit=).
	TrustGraphCoreDefault = 100
	TrustGraphCoreMax     = 250
	// TrustGraphNodesPerCore is the node cap as a multiple of the core:
	// the core and its neighbours.
	TrustGraphNodesPerCore = 2
	// TrustGraphEdgesMax caps the edges returned, heaviest first.
	TrustGraphEdgesMax = 2000
	// trustGraphScanMax caps the rows read per edge kind.
	trustGraphScanMax = 20000
	// trustGraphTTL is how long a built graph is reused, in seconds.
	trustGraphTTL = 300
)

// TrustGraphEdgeKinds are the edge kinds, in the order the legend shows them.
var TrustGraphEdgeKinds = []string{"vouch", "work_accept", "witness", "key_link"}

// TrustGraph is the public trust network as /api/trust/graph serves it.
type TrustGraph struct {
	Mode          string           `json:"mode"`
	Run           int64            `json:"run"`
	AsOf          int64            `json:"as_of"`
	ParamsVersion int64            `json:"params_version"`
	Limits        TrustGraphLimits `json:"limits"`
	Nodes         []TrustGraphNode `json:"nodes"`
	Edges         []TrustGraphEdge `json:"edges"`
	// Truncated counts what the caps left out: accounts with standing
	// beyond the core, neighbours beyond the node cap, edges beyond the
	// edge cap.
	Truncated TrustGraphLimits `json:"truncated"`
	Scope     string           `json:"scope"`
}

// TrustGraphLimits is a node and edge count: the caps, or what they cut.
type TrustGraphLimits struct {
	Core  int `json:"core"`
	Nodes int `json:"nodes"`
	Edges int `json:"edges"`
}

// TrustGraphNode is one identity: its fingerprint (the account), handle,
// standing in the latest run, band (allowance.Band: 1 signed, 2 proven,
// 3 trusted), and the kinds of its own costs (domain, wallet, github, pow,
// money, time_present, payments; never their values).
type TrustGraphNode struct {
	ID            string   `json:"id"`
	Handle        string   `json:"handle"`
	Standing      float64  `json:"standing"`
	StandingCents int64    `json:"standing_cents"`
	FakeCost      string   `json:"fake_cost"`
	Band          int64    `json:"band"`
	BandName      string   `json:"band_name"`
	Roots         []string `json:"roots"`
	Penalised     bool     `json:"penalised"`
	Core          bool     `json:"core"`
}

// TrustGraphEdge is one public edge between two shown identities, the acts
// of one kind from one to the other added up: weight is their summed act
// weight (a vouch its chosen weight, accepted work and a witness 10 each).
type TrustGraphEdge struct {
	From   string `json:"from"`
	To     string `json:"to"`
	Kind   string `json:"kind"`
	Count  int64  `json:"count"`
	Weight int64  `json:"weight"`
}

// trustGraphCache keeps the last graph per core size for trustGraphTTL.
// It also keeps the trust layers (TrustLayer) by size.
type trustGraphCache struct {
	mu     sync.Mutex
	m      map[int]trustGraphEntry
	layers map[trustLayerKey]trustLayerEntry
}

type trustGraphEntry struct {
	at int64
	g  *TrustGraph
}

// BandName names a standing band (allowance.Band): 1 signed, 2 proven,
// 3 trusted; anything else reads as signed.
func BandName(band int64) string {
	if band == int64(allowance.BandTrusted) || band == int64(allowance.BandProven) {
		return allowance.Band(band).Name()
	}
	return allowance.BandSigned.Name()
}

// graphScore is what the network shows of an account's standing.
type graphScore struct {
	cents, band int64
	roots       []string
	penalised   bool
}

// TrustGraph is the public trust network of the latest finished run with
// standing, limited to core accounts by standing and their neighbours.
func (s *Store) TrustGraph(ctx context.Context, core int) (*TrustGraph, error) {
	if s.config.Features.Trust == TrustOff {
		return nil, allowanceError("service_unavailable")
	}
	if core < 1 || core > TrustGraphCoreMax {
		core = TrustGraphCoreDefault
	}
	now := s.now().Unix()
	cache := &s.trust.graph
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if cache.m == nil {
		cache.m = map[int]trustGraphEntry{}
	}
	if e, ok := cache.m[core]; ok && now-e.at < trustGraphTTL {
		return e.g, nil
	}
	var g *TrustGraph
	err := (trustDB{s}).Read(ctx, func(q allowance.Querier) (err error) {
		g, err = buildTrustGraph(ctx, q, core, now)
		return err
	})
	if err != nil {
		return nil, err
	}
	g.Mode = s.config.Features.Trust.String()
	cache.m[core] = trustGraphEntry{now, g}
	return g, nil
}

type graphPair struct{ from, to, kind string }

func buildTrustGraph(ctx context.Context, q allowance.Querier, core int, now int64) (*TrustGraph, error) {
	g := &TrustGraph{Nodes: []TrustGraphNode{}, Edges: []TrustGraphEdge{},
		Limits: TrustGraphLimits{Core: core, Nodes: core * TrustGraphNodesPerCore, Edges: TrustGraphEdgesMax},
		Scope:  "public accounts only; edges are vouches, accepted work on public items, verified witnesses and verified key links; never votes, replies, mentions, DMs or private rooms"}
	if ok, err := tableExists(ctx, q, "trust_runs"); err != nil || !ok {
		return g, err
	}
	run, ok, err := trust.Latest(ctx, q)
	if err != nil {
		return nil, err
	}
	if !ok {
		return g, nil
	}
	g.Run, g.AsOf, g.ParamsVersion = run.ID, run.AsOf, run.Version

	// The core: public accounts with standing, highest first.
	scores := map[string]*graphScore{}
	var coreIDs []string
	const withStanding = `FROM trust_scores t WHERE t.run_id=? AND t.collateral>0 AND `
	var total int
	if err = q.QueryRowContext(ctx, "SELECT count(*) "+withStanding+publicAccountSQL("t.account"), g.Run).Scan(&total); err != nil {
		return nil, err
	}
	g.Truncated.Core = max(0, total-core)
	rows, err := q.QueryContext(ctx, "SELECT t.account,t.collateral,t.tier,t.parts "+withStanding+publicAccountSQL("t.account")+
		" ORDER BY t.collateral DESC, t.account LIMIT ?", g.Run, core)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var account, parts string
		var cents, band int64
		if err = rows.Scan(&account, &cents, &band, &parts); err != nil {
			rows.Close()
			return nil, err
		}
		scores[account] = newGraphScore(cents, band, parts)
		coreIDs = append(coreIDs, account)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return nil, err
	}
	inCore := map[string]bool{}
	for _, a := range coreIDs {
		inCore[a] = true
	}

	// Every public edge touching the core.
	agg := map[graphPair]*TrustGraphEdge{}
	add := func(from, to, kind string, weight int64) {
		if from == "" || to == "" || from == to || !(inCore[from] || inCore[to]) {
			return
		}
		k := graphPair{from, to, kind}
		e := agg[k]
		if e == nil {
			e = &TrustGraphEdge{From: from, To: to, Kind: kind}
			agg[k] = e
		}
		e.Count++
		e.Weight += weight
	}
	scan := func(query string, kind string, args ...any) error {
		r, err := q.QueryContext(ctx, query, append(args, trustGraphScanMax)...)
		if err != nil {
			return err
		}
		defer r.Close()
		for r.Next() {
			var from, to, payload string
			if err := r.Scan(&from, &to, &payload); err != nil {
				return err
			}
			w := int64(10)
			if kind == "vouch" {
				if n := vouchWeightOf(payload); n > 0 {
					w = int64(n)
				}
			}
			add(from, to, kind, w)
		}
		return r.Err()
	}
	if ok, err := tableExists(ctx, q, "vouches"); err != nil {
		return nil, err
	} else if ok {
		if err := scan(`SELECT v.voter_account,v.target_account,coalesce(r.signed_payload,'') FROM vouches v LEFT JOIN endorsement_records r ON r.seq=v.record_seq
 WHERE v.value=1 AND `+publicAccountSQL("v.voter_account")+` AND `+publicAccountSQL("v.target_account")+` ORDER BY v.record_seq DESC LIMIT ?`, "vouch"); err != nil {
			return nil, err
		}
	}
	if ok, err := tableExists(ctx, q, "work_transitions"); err != nil {
		return nil, err
	} else if ok {
		if err := scan(`SELECT ia.account,w.worker,'' FROM work_transitions t JOIN works w ON w.id=t.work_id
 JOIN events e ON e.id=w.id JOIN rooms r ON r.name=e.room JOIN identities ia ON ia.id=t.author
 WHERE t.operation='work.accept' AND w.state='accepted' AND w.worker<>'' AND r.visibility='public' AND e.hidden=0 AND e.kind<>'simulation'
 AND `+publicAccountSQL("ia.account")+` AND `+publicAccountSQL("w.worker")+` ORDER BY t.rowid DESC LIMIT ?`, "work_accept"); err != nil {
			return nil, err
		}
	}
	if ok, err := tableExists(ctx, q, "link_witnesses"); err != nil {
		return nil, err
	} else if ok {
		if err := scan(`SELECT iw.account,ia.account,'' FROM link_witnesses l JOIN identities iw ON iw.id=l.witness JOIN identities ia ON ia.id=l.agent
 WHERE l.verdict='verified' AND l.superseded_at=0 AND `+publicAccountSQL("iw.account")+` AND `+publicAccountSQL("ia.account")+` ORDER BY l.seq DESC LIMIT ?`, "witness"); err != nil {
			return nil, err
		}
	}
	if ok, err := tableExists(ctx, q, "identity_links"); err != nil {
		return nil, err
	} else if ok {
		if err := scan(`SELECT i.account,o.account,'' FROM identity_links l JOIN identities i ON i.id=l.agent JOIN identities o ON o.public_key=l.value
 WHERE l.kind='ed25519' AND l.state='verified' AND i.successor='' AND i.revoked_at=0 AND o.account<>i.account AND `+publicAccountSQL("i.account")+` AND `+publicAccountSQL("o.account")+`
 ORDER BY l.rowid DESC LIMIT ?`, "key_link"); err != nil {
			return nil, err
		}
	}

	// Neighbours of the core, by standing then by ties to the core, up to the node cap.
	ties := map[string]int{}
	for k := range agg {
		for _, a := range []string{k.from, k.to} {
			if !inCore[a] {
				ties[a]++
			}
		}
	}
	var neighbours []string
	for a := range ties {
		neighbours = append(neighbours, a)
	}
	if err := readStandingParts(ctx, q, g.Run, neighbours, scores); err != nil {
		return nil, err
	}
	cents := func(a string) int64 {
		if p := scores[a]; p != nil {
			return p.cents
		}
		return 0
	}
	sort.Slice(neighbours, func(i, j int) bool {
		a, b := neighbours[i], neighbours[j]
		if cents(a) != cents(b) {
			return cents(a) > cents(b)
		}
		if ties[a] != ties[b] {
			return ties[a] > ties[b]
		}
		return a < b
	})
	room := g.Limits.Nodes - len(coreIDs)
	if len(neighbours) > room {
		g.Truncated.Nodes = len(neighbours) - room
		neighbours = neighbours[:room]
	}
	shown := map[string]bool{}
	ids := append(append([]string{}, coreIDs...), neighbours...)
	for _, a := range ids {
		shown[a] = true
	}

	// Edges between shown identities, heaviest first, up to the edge cap.
	for _, e := range agg {
		if shown[e.From] && shown[e.To] {
			g.Edges = append(g.Edges, *e)
		}
	}
	sort.Slice(g.Edges, func(i, j int) bool {
		a, b := g.Edges[i], g.Edges[j]
		if a.Weight != b.Weight {
			return a.Weight > b.Weight
		}
		if a.From != b.From {
			return a.From < b.From
		}
		if a.To != b.To {
			return a.To < b.To
		}
		return a.Kind < b.Kind
	})
	if len(g.Edges) > TrustGraphEdgesMax {
		g.Truncated.Edges = len(g.Edges) - TrustGraphEdgesMax
		g.Edges = g.Edges[:TrustGraphEdgesMax]
	}

	// Node details: handle, penalty, roots by kind.
	handles, err := readHandles(ctx, q, ids)
	if err != nil {
		return nil, err
	}
	for _, a := range ids {
		n := TrustGraphNode{ID: a, Handle: handles[a], Band: int64(allowance.BandSigned), Roots: []string{}, Core: inCore[a]}
		if p := scores[a]; p != nil {
			n.StandingCents, n.Band, n.Roots, n.Penalised = p.cents, p.band, p.roots, p.penalised
		}
		n.Standing, n.FakeCost, n.BandName = trust.StandingScore(n.StandingCents), trust.FakeCostText(n.StandingCents), BandName(n.Band)
		g.Nodes = append(g.Nodes, n)
	}
	return g, nil
}

// newGraphScore reads a trust_scores row's standing, band and parts: the
// kinds of its own costs (never their values) and whether it is penalised.
func newGraphScore(cents, band int64, parts string) *graphScore {
	gs := &graphScore{cents: cents, band: band, roots: []string{}}
	var p trust.Parts
	if json.Unmarshal([]byte(parts), &p) != nil {
		return gs
	}
	have := map[string]bool{}
	for _, it := range p.World {
		if it.Cents > 0 {
			have[trustWorldKind(it)] = true
		}
	}
	for _, k := range TrustWorldKinds {
		if have[k] {
			gs.roots = append(gs.roots, k)
		}
	}
	gs.penalised = p.Penalty != nil && p.Penalty.Role == "member"
	return gs
}

// readStandingParts adds the run's standing of these accounts to into.
func readStandingParts(ctx context.Context, q allowance.Querier, run int64, accounts []string, into map[string]*graphScore) error {
	for start := 0; start < len(accounts); start += 200 {
		chunk := accounts[start:min(len(accounts), start+200)]
		args := []any{run}
		for _, a := range chunk {
			args = append(args, a)
		}
		r, err := q.QueryContext(ctx, "SELECT account,collateral,tier,parts FROM trust_scores WHERE run_id=? AND account IN (?"+strings.Repeat(",?", len(chunk)-1)+")", args...)
		if err != nil {
			return err
		}
		for r.Next() {
			var a, parts string
			var cents, band int64
			if err = r.Scan(&a, &cents, &band, &parts); err != nil {
				r.Close()
				return err
			}
			into[a] = newGraphScore(cents, band, parts)
		}
		r.Close()
		if err = r.Err(); err != nil {
			return err
		}
	}
	return nil
}

// readHandles is each account's handle: the newest of its keys' handles.
func readHandles(ctx context.Context, q allowance.Querier, accounts []string) (map[string]string, error) {
	out := map[string]string{}
	for start := 0; start < len(accounts); start += 200 {
		chunk := accounts[start:min(len(accounts), start+200)]
		args := []any{}
		for _, a := range chunk {
			args = append(args, a)
		}
		r, err := q.QueryContext(ctx, "SELECT account,handle FROM identities WHERE handle<>'' AND account IN (?"+strings.Repeat(",?", len(chunk)-1)+") ORDER BY created_at", args...)
		if err != nil {
			return nil, err
		}
		for r.Next() {
			var a, h string
			if err = r.Scan(&a, &h); err != nil {
				r.Close()
				return nil, err
			}
			out[a] = h
		}
		r.Close()
		if err = r.Err(); err != nil {
			return nil, err
		}
	}
	return out, nil
}
