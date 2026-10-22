#!/usr/bin/env python3
"""Independent verifier for SwarmMemo's trust runs (RFC0012 §4.8). Stdlib only.

Three commands:

  recompute.py verify EXPORT.jsonl [--service swarmmemo.com]
      Checks every line of /v1/export?stream=endorsements offline: the Ed25519
      signature over signed_payload with public_key (a pure-Python RFC 8032
      verifier, cofactorless like Go's crypto/ed25519), and that the signed
      command is the record (service, operation, message or target, value,
      sponsor). legacy_vote and unsigned records carry weight 0 and are counted,
      not verified. Exit status 1 if any signed record fails.

  recompute.py endorsements EXPORT.jsonl [--service swarmmemo.com]
      Verifies the export as above and prints each record as a trust input
      line ({"type":"endorsement",...}); unsigned votes become kind "unsigned".

  recompute.py run SNAPSHOT.jsonl
      Recomputes a trust run from its inputs and prints the output as canonical
      JSON (sorted keys, no spaces), which must equal the published run byte for
      byte. The input is the run's snapshot: one JSON record per line, typed
      meta, params, account, post, endorsement, proof, breaker, transfer, claim,
      prior, penalty and sponsorship, and from parameter version 2 edge and
      spend, the format of internal/trust's golden fixtures
      (testdata/golden_inputs.jsonl, testdata/golden_standing_v2_inputs.jsonl,
      testdata/golden_standing_v3_inputs.jsonl, testdata/golden_standing_v4_inputs.jsonl,
      testdata/golden_standing_inputs.jsonl). From parameter version 3 a proof
      may carry registered_at and a spend to and link_value (its payee); from
      version 4 a vouch may carry weight; from version 5 a proof of an assessed
      kind (wallet, github, pow) may carry root and assessed.

The algorithm is the published one (RFC0012 §4.2–4.5), restated here from the
specification rather than translated from the Go reference, and checked against
the reference's golden fixtures by test_recompute.py. From parameter version 2
the run also computes standing (RFC0015 §3): seeded personalized PageRank over
endorse edges, with oppose edges subtracted locally (compute_standing()); version
3 (standing.rule 1) returns a dangling node's pass to the seeds, reports
c / (1 − pass), leaves self-dealt spend out of the seed, caps spend's seed and
prices a domain by its registration age when known; version 4 (rule 2) gives
each act its kind's absolute weight, passes only pass × W / (K + W) along edges
of total weight W (the rest returns to the seeds) and reports c; version 6
(rule 3) replaces the propagation with stakes: a vouch, an accepted work item and
a verified witness move a share of the endorser's own standing to the target, and
votes, witness verdicts and those acts are positions settled by later independent
endorsement, losers paying winners within a pot (run_stakes()). Every amount is an
integer; divisions truncate toward zero as Go's do; curves are published daily
factors applied one whole day at a time with floor. The flow is Dinic's
algorithm specified down to edge insertion order and the path search, since a
maximum flow's split over sinks is not unique.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import sys

DAY = 86400
PPM = 1_000_000


# ---------------------------------------------------------------------------
# Integer and JSON helpers


def gdiv(a: int, b: int) -> int:
    """Go's integer division: truncates toward zero."""
    q = abs(a) // abs(b)
    return q if (a >= 0) == (b > 0) else -q


def day_of(t: int) -> int:
    return -gdiv(-t + DAY - 1, DAY) if t < 0 else t // DAY


def canonical(value) -> str:
    """Canonical JSON: sorted keys, no whitespace, UTF-8, no HTML escaping."""
    text = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return text.replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")


def _go_quote(s: str) -> str:
    """A string as Go's json.Marshal writes it (HTML characters escaped)."""
    text = json.dumps(s, ensure_ascii=False)
    for raw, esc in (("<", "\\u003c"), (">", "\\u003e"), ("&", "\\u0026"), ("\u2028", "\\u2028"), ("\u2029", "\\u2029")):
        text = text.replace(raw, esc)
    return text


# Record fields in the reference's declaration order, with their zero values:
# a record's sort key is its json.Marshal form, every field omitempty but type.
RECORD_FIELDS = [
    ("type", ""), ("schema", 0), ("as_of", 0), ("prior_runs", 0), ("pause_new_keys_since", 0), ("events_seq", 0),
    ("endorsements_seq", 0), ("ledger_seq", 0), ("version", 0), ("body", None), ("account", ""), ("created_at", 0),
    ("first_seen", 0), ("id", ""), ("reply_to", ""), ("reply_to_account", ""), ("seq", 0), ("kind", ""), ("voter", ""),
    ("target", ""), ("message_id", ""), ("value", 0), ("sponsor", False), ("weight", 0), ("link_value", ""), ("state", ""),
    ("checked_at", 0), ("link_account", ""), ("registered_at", 0), ("root", ""), ("assessed", 0), ("started_at", 0), ("trust_until", 0), ("from", ""), ("to", ""),
    ("amount", 0), ("day", 0), ("claimed", 0), ("spent", 0), ("flow_sum", 0), ("standing", False), ("evidence", ""),
    ("fraction_ppm", 0), ("ends_at", 0), ("invitee", ""), ("sponsor_account", ""), ("high_water", 0),
]
FIELD_ZERO = dict(RECORD_FIELDS)
RECORD_TYPES = {"meta", "params", "account", "post", "endorsement", "proof", "breaker", "transfer", "claim", "prior",
                "penalty", "sponsorship", "edge", "spend",
                # RFC 0020 judgements_shadow inputs: the Go run's shadow section reads
                # them; the output this script reproduces never does.
                "review", "owner"}


def record_key(r: dict) -> str:
    parts = []
    for name, zero in RECORD_FIELDS:
        value = r.get(name, zero)
        if name != "type" and (value == zero or value is None):
            continue
        if isinstance(value, bool):
            encoded = "true" if value else "false"
        elif isinstance(value, int):
            encoded = str(value)
        elif isinstance(value, str):
            encoded = _go_quote(value)
        else:
            encoded = json.dumps(value, separators=(",", ":"), ensure_ascii=False)
        parts.append(_go_quote(name) + ":" + encoded)
    return "{" + ",".join(parts) + "}"


class Rec(dict):
    """A trust input record; absent fields read as their zero value."""

    def __getattr__(self, name):
        return self.get(name, FIELD_ZERO.get(name))


# ---------------------------------------------------------------------------
# Snapshot and parameters


class InputError(ValueError):
    pass


PARAM_KEYS = {
    "schema", "collateral_unit", "seeds", "seeds_reason", "service_accounts", "proofs", "domain_suffixes",
    "proof_fresh_days", "history", "window_days", "n_max", "k_out", "edges", "unit_per_share", "edge_cap_ppm",
    "lambda_ppm", "root_cap_shares", "fill_steps", "own_avg_runs", "active_days", "activity_days", "seeds_b",
    "max_work", "max_seconds", "theta_trusted", "theta_proven", "endorsement_unit_price", "weight_cap_ppm",
    "weight_per_unit_ppm", "detectors", "liability", "sponsor",
}
PARAM_SECTIONS = {
    "history": {"day_price", "days_cap", "half_life_days", "day_factor_ppm"},
    "seeds_b": {"min_roots", "theta_anchor", "min_age_days", "active_days", "of_days", "min_members"},
    "detectors": {"version", "funnel_k", "funnel_days", "funnel_spend_ppm", "ring_min", "ring_inside_ppm"},
    "liability": {"phi_ppm", "phi_max_ppm", "penalty_days", "edge_days"},
    "sponsor": {"window_days", "slots_per_share", "dividend_ppm", "dividend_days", "daily_cap", "resource"},
}
PROOF_KEYS = {"forge", "rent", "curve", "half_life_days", "day_factor_ppm"}
# From parameter version 5: the optional assessed rows and the rule of each.
ASSESSED_KINDS = {"wallet": "capped", "github": "capped", "pow": "saturating"}
ASSESSED_MAX = 10 ** 15
# Payment kinds that are USDC settled on chain to the payee's payout address
# (trust.SettledPaymentKind).
SETTLED_PAYMENT_KINDS = {"work_usdc", "offering"}
STANDING_KEYS = {"mode", "half_life_days", "day_factor_ppm", "pass_ppm", "iterations", "arbiter_seed_cents", "anon_seed_cents",
                 "credits_per_cent", "theta1_cents", "theta2_cents", "v0_ppm", "c_ref_cents"}
# From parameter version 3 (the simulation's fixes); each is omitted when zero.
STANDING_KEYS_V3 = {"rule", "v_floor_cents", "spend_cap_cents", "funded_days"}
# From parameter version 4 (rule 2, absolute weights).
STANDING_KEYS_V4 = {"keep_weight", "edge_weights", "vouch_weight_max"}
# From parameter version 6 (rule 3, endorsements are stakes).
STANDING_KEYS_V6 = {"stake_ppm", "stake_budget_ppm", "prior_min_posts"}
EDGE_WEIGHT_KINDS = {"vote", "down_vote", "vouch", "work_accept", "witness"}
EDGE_KEYS = {"base_ppm", "half_life_days", "day_factor_ppm"}


def check_params(body: dict) -> None:
    """Strict shape check: every field present, none unknown, integers where
    integers belong. Bounds are the reference's to publish; a verifier only
    needs to refuse what it cannot read the same way."""
    def exact(obj, keys, where):
        if not isinstance(obj, dict) or set(obj) != keys:
            raise InputError(f"params {where}: fields must be exactly {sorted(keys)}")
    if "standing" in body:
        exact(body, PARAM_KEYS | {"standing"}, "body")
        st = body["standing"]
        if isinstance(st, dict) and (st.get("rule", 0) >= 4 or "judgements" in st):
            raise InputError("params standing: rule 4 (parameter version 7, RFC 0020's marks) is retired (RFC 0021) and verified by no tool; "
                             "its snapshot and output_sha256 stay published")
        extra = STANDING_KEYS_V3 | STANDING_KEYS_V4 | STANDING_KEYS_V6
        if not isinstance(st, dict) or not STANDING_KEYS <= set(st) <= STANDING_KEYS | extra:
            raise InputError(f"params standing: fields must be {sorted(STANDING_KEYS)}, plus any of {sorted(extra)}")
        if body["standing"]["mode"] not in ("shadow", "active"):
            raise InputError("params standing.mode must be shadow or active")
        if st.get("rule", 0) >= 2:
            if set(st) & STANDING_KEYS_V4 != STANDING_KEYS_V4:
                raise InputError(f"params standing: rule 2 needs {sorted(STANDING_KEYS_V4)}")
            exact(st["edge_weights"], EDGE_WEIGHT_KINDS, "standing.edge_weights")
        elif set(st) & STANDING_KEYS_V4:
            raise InputError(f"params standing: {sorted(STANDING_KEYS_V4)} need rule 2")
        if st.get("rule", 0) >= 3:
            if set(st) & STANDING_KEYS_V6 != STANDING_KEYS_V6:
                raise InputError(f"params standing: rule 3 needs {sorted(STANDING_KEYS_V6)}")
        elif set(st) & STANDING_KEYS_V6:
            raise InputError(f"params standing: {sorted(STANDING_KEYS_V6)} need rule 3")
    else:
        exact(body, PARAM_KEYS, "body")
    for section, keys in PARAM_SECTIONS.items():
        exact(body[section], keys, section)
    for kind in ("domain", "ed25519", "board", "url", "nostr"):
        exact(body["proofs"].get(kind), PROOF_KEYS, "proofs." + kind)
    for kind, rule in ASSESSED_KINDS.items():
        if kind in body["proofs"]:
            exact(body["proofs"][kind], PROOF_KEYS | {"assess", "units_per_cent"}, "proofs." + kind)
            if body["proofs"][kind]["assess"] != rule or not isinstance(body["proofs"][kind]["units_per_cent"], int) \
                    or body["proofs"][kind]["units_per_cent"] < 1:
                raise InputError(f"params proofs.{kind}: assess must be {rule} with a positive units_per_cent")
    if not {"domain", "ed25519", "board", "url", "nostr"} <= set(body["proofs"]) <= {"domain", "ed25519", "board", "url", "nostr"} | set(ASSESSED_KINDS):
        raise InputError("params proofs: exactly domain, ed25519, board, url and nostr, and optionally wallet, github and pow")
    for kind in ("vote", "vouch", "reply", "legacy_vote"):
        exact(body["edges"].get(kind), EDGE_KEYS, "edges." + kind)
    if set(body["edges"]) != {"vote", "vouch", "reply", "legacy_vote"}:
        raise InputError("params edges: exactly vote, vouch, reply and legacy_vote")
    if body["schema"] != 1:
        raise InputError("params schema must be 1")

    def ints(obj, where):
        for k, v in obj.items():
            if isinstance(v, dict):
                ints(v, where + "." + k)
            elif isinstance(v, bool) or (isinstance(v, float)):
                raise InputError(f"params {where}.{k} must be an integer")
    ints(body, "body")


class Snapshot:
    def __init__(self):
        self.meta = Rec()
        self.params = None
        self.params_version = 0
        self.lists = {t: [] for t in RECORD_TYPES - {"meta", "params"}}

    def __getattr__(self, name):
        lists = self.__dict__.get("lists", {})
        singular = {"accounts": "account", "posts": "post", "endorsements": "endorsement", "proofs": "proof",
                    "breakers": "breaker", "transfers": "transfer", "claims": "claim", "priors": "prior",
                    "penalties": "penalty", "sponsorships": "sponsorship", "acts": "edge", "spends": "spend"}
        if name in singular:
            return lists[singular[name]]
        raise AttributeError(name)


def read_snapshot(lines) -> Snapshot:
    snap = Snapshot()
    for n, line in enumerate(lines, 1):
        line = line.strip()
        if not line:
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError as e:
            raise InputError(f"line {n}: {e}") from e
        if not isinstance(raw, dict) or raw.get("type") not in RECORD_TYPES:
            raise InputError(f"line {n}: unknown record type {raw.get('type') if isinstance(raw, dict) else raw!r}")
        unknown = set(raw) - set(FIELD_ZERO)
        if unknown:
            raise InputError(f"line {n}: unknown field(s) {sorted(unknown)}")
        for k, v in raw.items():
            zero = FIELD_ZERO[k]
            if k == "body":
                continue
            if isinstance(zero, bool) != isinstance(v, bool) or type(v) is not type(zero):
                raise InputError(f"line {n}: field {k} has the wrong type")
        rec = Rec(raw)
        if rec.type == "meta":
            snap.meta = rec
        elif rec.type == "params":
            check_params(rec.body)
            snap.params = rec.body
            snap.params_version = rec.version
        else:
            snap.lists[rec.type].append(rec)
    if snap.params is None:
        raise InputError("the snapshot has no params record")
    return snap


# ---------------------------------------------------------------------------
# Curves, roots


def assessed_contribution(price, assessed):
    """What an assessed root adds, in cents: min(cap, v) (capped) or
    cap * v / (v + cap) (saturating), v = assessed / units_per_cent, exact."""
    u = price.get("units_per_cent", 0)
    if u <= 0:
        return 0
    ceiling = min(price["forge"], price["rent"])
    fallback = price.get("fallback_cents", 0)
    if assessed <= 0:
        return min(ceiling, max(0, fallback)) if price["assess"] == "capped" else 0
    assessed = min(assessed, ASSESSED_MAX)
    if price["assess"] == "capped":
        return min(ceiling, max(assessed // u, fallback))
    if price["assess"] == "saturating":
        return ceiling * assessed // (assessed + ceiling * u) if ceiling > 0 else 0
    return 0


def assessed_value(price, assessed):
    """assessed_contribution without a capped row's fallback_cents: what the
    assessment itself is worth (C492: the floor counts once per kind and
    node root)."""
    u = price.get("units_per_cent", 0)
    if u <= 0 or assessed <= 0:
        return 0
    ceiling = min(price["forge"], price["rent"])
    assessed = min(assessed, ASSESSED_MAX)
    if price["assess"] == "capped":
        return min(ceiling, assessed // u)
    if price["assess"] == "saturating":
        return ceiling * assessed // (assessed + ceiling * u) if ceiling > 0 else 0
    return 0


class Curves:
    """1e6 × f^days, one whole day at a time with floor; ages past 3650 days
    use 3650. The run never evaluates a float."""

    def __init__(self):
        self.tables = {}

    def decay(self, factor: int, days: int) -> int:
        if days <= 0:
            return PPM
        days = min(days, 3650)
        table = self.tables.setdefault(factor, [PPM])
        while len(table) <= days:
            table.append(table[-1] * factor // PPM)
        return table[days]

    def ramp(self, factor: int, days: int) -> int:
        return PPM - self.decay(factor, days)


class UnionFind(dict):
    """Union-find over strings; the smaller representative wins a union."""

    def find(self, x):
        while True:
            p = self.get(x)
            if p is None or p == x:
                return x
            gp = self.get(p, "")
            if gp != "" and gp != p:
                self[x] = gp
            x = p

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            return
        if rb < ra:
            ra, rb = rb, ra
        self[ra] = ra
        self[rb] = ra


def domain_root(domain: str, suffixes: set) -> str:
    """"domain:" + one label under the longest listed multi-label public
    suffix, else the last two labels."""
    d = domain.lower()
    if d.endswith("."):
        d = d[:-1]
    labels = d.split(".")
    keep = 2
    for i in range(1, len(labels) - 1):
        if ".".join(labels[i:]) in suffixes:
            keep = len(labels) - i + 1
            break
    keep = min(keep, len(labels))
    return "domain:" + ".".join(labels[len(labels) - keep:])


# ---------------------------------------------------------------------------
# Dinic max-flow, specified exactly


class WorkExceeded(RuntimeError):
    pass


class Network:
    """add(u, v, c) appends edge e = u→v (capacity c) and its reverse e^1
    (capacity 0) to u's and v's lists. A phase is a BFS from s over each
    node's list in insertion order, then repeated single-path searches with a
    per-node pointer: at u take the first edge from it[u] on with residual > 0
    into level[u]+1; at a dead end step back and advance the parent's pointer;
    reaching t push the bottleneck. Every edge examined counts as work."""

    def __init__(self, n: int, max_work: int, work: int):
        self.adj = [[] for _ in range(n)]
        self.to = []
        self.cap = []
        self.work = work
        self.max_work = max_work

    def add(self, u: int, v: int, c: int) -> int:
        e = len(self.to)
        self.to += [v, u]
        self.cap += [c, 0]
        self.adj[u].append(e)
        self.adj[v].append(e + 1)
        return e

    def flow_on(self, e: int) -> int:
        return self.cap[e ^ 1]

    def tick(self):
        self.work += 1
        if self.work > self.max_work:
            raise WorkExceeded("max_work exceeded")

    def maxflow(self, s: int, t: int):
        n = len(self.adj)
        while True:
            level = [-1] * n
            level[s] = 0
            queue = [s]
            head = 0
            while head < len(queue):
                u = queue[head]
                head += 1
                for e in self.adj[u]:
                    self.tick()
                    v = self.to[e]
                    if self.cap[e] > 0 and level[v] < 0:
                        level[v] = level[u] + 1
                        queue.append(v)
            if level[t] < 0:
                return
            it = [0] * n
            while self._augment(s, t, level, it) > 0:
                pass

    def _augment(self, s, t, level, it) -> int:
        path = []
        u = s
        while True:
            if u == t:
                f = 1 << 62
                for e in path:
                    f = min(f, self.cap[e])
                for e in path:
                    self.cap[e] -= f
                    self.cap[e ^ 1] += f
                return f
            advanced = False
            edges = self.adj[u]
            while it[u] < len(edges):
                self.tick()
                e = edges[it[u]]
                v = self.to[e]
                if self.cap[e] > 0 and level[v] == level[u] + 1:
                    path.append(e)
                    u = v
                    advanced = True
                    break
                it[u] += 1
            if advanced:
                continue
            if not path:
                return 0
            e = path.pop()
            u = self.to[e ^ 1]
            it[u] += 1


def run_flow(graph: dict, seeds: list, pool: int, max_work: int, work: int):
    """Stake-bounded capacity flow from seeds (sorted node indices): in-node i,
    out-node n+i, hub j at 2n+j, then S and T. Inserted in order: in→out
    transit edges by node (a seed passes the whole pool); graph edges by (src,
    dst); sink edges by node, capacity 0, raised to U×k/steps at level k; hub→T
    edges; S→seed edges, pool/len(seeds) each."""
    n = graph["n"]
    node_flow, edge_flow = [0] * n, [0] * len(graph["src"])
    if not seeds or n == 0:
        return node_flow, edge_flow, work
    hubs = graph["hubs"]
    S, T = 2 * n + hubs, 2 * n + hubs + 1
    net = Network(T + 1, max_work, work)
    seed_set = set(seeds)
    for i in range(n):
        net.add(i, n + i, pool if i in seed_set else graph["transit"][i])
    edge_ids = []
    for k in range(len(graph["src"])):
        c = graph["cap"][k]
        edge_ids.append(net.add(n + graph["src"][k], graph["dst"][k], c) if c > 0 else -1)
    sink = []
    for i in range(n):
        hub = graph["hub"][i]
        sink.append(net.add(i, 2 * n + hub if hub >= 0 else T, 0))
    for j in range(hubs):
        net.add(2 * n + j, T, graph["hub_cap"])
    per_seed = max(1, pool // len(seeds))
    for s in seeds:
        net.add(S, s, per_seed)
    done = 0
    for k in range(1, graph["steps"] + 1):
        level = graph["node_cap"] * k // graph["steps"]
        for e in sink:
            net.cap[e] += level - done
        done = level
        net.maxflow(S, T)
    for i, e in enumerate(sink):
        node_flow[i] = net.flow_on(e)
    for k, e in enumerate(edge_ids):
        if e >= 0:
            edge_flow[k] = net.flow_on(e)
    return node_flow, edge_flow, net.work


# ---------------------------------------------------------------------------
# Detectors


def evidence_id(kind: str, D: int, members: list) -> str:
    digest = hashlib.sha256(f"{kind}\n{D}\n{','.join(members)}".encode()).hexdigest()
    return f"{kind}-{digest[:24]}"


def strongly_connected(n: int, edges: list) -> list:
    """Tarjan's components, visiting nodes 0..n-1 and each node's edges in
    (src, dst) order."""
    adj = [[] for _ in range(n)]
    for src, dst, _ in edges:
        adj[src].append(dst)
    index, low, on = [-1] * n, [0] * n, [False] * n
    stack, out, counter = [], [], [0]

    sys.setrecursionlimit(max(sys.getrecursionlimit(), 4 * n + 1000))

    def visit(v):
        index[v] = low[v] = counter[0]
        counter[0] += 1
        stack.append(v)
        on[v] = True
        for w in adj[v]:
            if index[w] < 0:
                visit(w)
                low[v] = min(low[v], low[w])
            elif on[w]:
                low[v] = min(low[v], index[w])
        if low[v] == index[v]:
            comp = []
            while True:
                w = stack.pop()
                on[w] = False
                comp.append(w)
                if w == v:
                    break
            out.append(comp)

    for v in range(n):
        if index[v] < 0:
            visit(v)
    return out


def detect(p, snap, as_of, D, service, nodes, edges) -> list:
    """funnel: a recipient of transfers from ≥ funnel_k distinct accounts in
    the last funnel_days, each of which spent ≤ funnel_spend_ppm of its claims
    those days. ring: a strongly connected set of ≥ ring_min nodes, each taking
    ≥ ring_inside_ppm of its inbound weight from inside, sharing a member with
    a funnel."""
    d = p["detectors"]
    out = []
    start = as_of - d["funnel_days"] * DAY
    claimed, spent = {}, {}
    for r in snap.claims:
        if D - d["funnel_days"] <= r.day < D:
            claimed[r.account] = claimed.get(r.account, 0) + r.claimed
            spent[r.account] = spent.get(r.account, 0) + r.spent
    senders = {}
    for r in snap.transfers:
        f, t = r["from"] if "from" in r else "", r.to
        if r.created_at < start or r.created_at >= as_of or f == t or f == "" or t == "" or f in service or t in service or r.amount <= 0:
            continue
        senders.setdefault(t, set()).add(f)
    in_funnel = {}
    for to in sorted(senders):
        farm = [s for s in senders[to] if claimed.get(s, 0) > 0 and spent.get(s, 0) * PPM <= d["funnel_spend_ppm"] * claimed[s]]
        if len(farm) < d["funnel_k"]:
            continue
        members = sorted(farm + [to])
        ev = {"id": evidence_id("funnel", D, members), "kind": "funnel", "members": members, "detector_version": d["version"],
              "detail": canonical({"recipient": to, "senders": len(farm), "window_days": d["funnel_days"]})}
        for m in members:
            in_funnel.setdefault(m, ev["id"])
        out.append(ev)
    if not in_funnel:
        return out
    for scc in strongly_connected(len(nodes), edges):
        if len(scc) < d["ring_min"]:
            continue
        inside = set(scc)
        inw, total = {}, {}
        for src, dst, w in edges:
            if dst in inside:
                total[dst] = total.get(dst, 0) + w
                if src in inside:
                    inw[dst] = inw.get(dst, 0) + w
        ok = all(total.get(v, 0) != 0 and inw.get(v, 0) * PPM >= d["ring_inside_ppm"] * total[v] for v in scc)
        members = sorted(nodes[v] for v in scc)
        funnels = [in_funnel[m] for m in members if m in in_funnel]
        if not ok or not funnels:
            continue
        out.append({"id": evidence_id("ring", D, members), "kind": "ring", "members": members, "detector_version": d["version"],
                    "detail": canonical({"size": len(members), "funnel": min(funnels)})})
    out.sort(key=lambda e: e["id"])
    return out


# ---------------------------------------------------------------------------
# The run


def compute(snap: Snapshot) -> dict:
    p = snap.params
    as_of = snap.meta.as_of
    D = day_of(as_of)
    ws = as_of - p["window_days"] * DAY
    U = p["unit_per_share"]
    cv = Curves()
    service = set(p["service_accounts"])
    edges_p = p["edges"]

    first_seen = {}
    for r in snap.accounts:
        if r.first_seen > 0 and (first_seen.get(r.account, 0) == 0 or r.first_seen < first_seen[r.account]):
            first_seen[r.account] = r.first_seen

    # Posts in the window, and activity.
    posts = sorted((r for r in snap.posts if ws <= r.created_at < as_of and r.account != "" and r.account not in service),
                   key=lambda r: (r.created_at, r.id))
    post_by_id, activity, last_seen = {}, {}, {}

    def active(a, t):
        activity.setdefault(a, set()).add(day_of(t))

    def seen(a, t):
        if t > last_seen.get(a, 0):
            last_seen[a] = t

    for r in posts:
        post_by_id[r.id] = r
        active(r.account, r.created_at)
        seen(r.account, r.created_at)

    # Endorsements: the latest record per vote (voter, message) and per vouch
    # (voter, target) decides.
    ends = sorted((r for r in snap.endorsements if r.created_at < as_of and r.voter != "" and r.voter not in service), key=lambda r: r.seq)
    latest_vote, latest_vouch = {}, {}
    for r in ends:
        if r.kind in ("vote", "legacy_vote", "unsigned"):
            latest_vote[(r.voter, r.message_id)] = r
        elif r.kind == "vouch":
            latest_vouch[(r.voter, r.target)] = r
        if r.created_at >= ws:
            active(r.voter, r.created_at)
            seen(r.voter, r.created_at)
            if r.target != "" and r.target not in service:
                seen(r.target, r.created_at)
    current = sorted(list(latest_vote.values()) + list(latest_vouch.values()), key=lambda r: r.seq)
    down_votes = {}
    for r in current:
        if r.kind == "vote" and r.value == -1 and r.created_at >= ws and r.target != "":
            down_votes[r.target] = down_votes.get(r.target, 0) + 1

    # Nodes: seeds first, then the most recently active, up to n_max.
    candidates = sorted((a for a in last_seen if a not in service), key=lambda a: (-last_seen[a], a))
    is_node = {s for s in p["seeds"] if s not in service}
    for a in candidates:
        if len(is_node) >= p["n_max"]:
            break
        is_node.add(a)
    nodes = sorted(is_node)
    index = {a: i for i, a in enumerate(nodes)}

    # Roots: fresh verified domains and attached ed25519 keys join accounts.
    suffixes = set(p["domain_suffixes"])
    proofs = sorted(snap.proofs, key=record_key)
    fresh = as_of - p["proof_fresh_days"] * DAY

    def counts(r):
        if p["proofs"].get(r.kind, {}).get("assess", ""):
            return r.state == "verified" and fresh <= r.checked_at <= as_of and r.created_at <= as_of
        if r.kind == "domain":
            return r.state == "verified" and fresh <= r.checked_at <= as_of and r.created_at <= as_of
        if r.kind == "ed25519":
            return r.state in ("proof_attached", "verified") and r.created_at <= as_of
        return r.state == "verified" and r.created_at <= as_of

    roots = UnionFind()
    for r in proofs:
        if r.account in service or not counts(r):
            continue
        if r.kind == "domain":
            roots.union(r.account, domain_root(r.link_value, suffixes))
        elif r.kind == "ed25519" and r.link_account != "" and r.link_account not in service:
            roots.union(r.account, r.link_account)
    label = {}
    for x in list(roots):
        rep = roots.find(x)
        cur = label.get(rep)
        is_domain = x.startswith("domain:")
        cur_domain = cur is not None and cur.startswith("domain:")
        if cur is None or (is_domain and not cur_domain) or (is_domain == cur_domain and x < cur):
            label[rep] = x

    def root_of(a):
        return label[roots.find(a)] if a in roots else a

    flow_sum, standing = {}, set()
    for r in snap.priors:
        flow_sum[r.account] = flow_sum.get(r.account, 0) + r.flow_sum
        if r.standing:
            standing.add(r.account)

    # Breakers, pause-new-keys and active penalties.
    reset = {r.account for r in snap.breakers if r.started_at <= as_of < r.trust_until}
    since = snap.meta.pause_new_keys_since
    if since > 0:
        reset |= {a for a, t in first_seen.items() if t > since}
    penalty = {}
    for r in snap.penalties:
        if r.ends_at > as_of and r.fraction_ppm > penalty.get(r.account, 0):
            penalty[r.account] = min(r.fraction_ppm, PPM)

    # Edge contributions.
    contribs = []
    for r in current:
        if r.created_at < ws or r.target == "" or r.value != 1:
            continue
        if r.kind in ("vote", "legacy_vote", "vouch"):
            contribs.append((r.voter, r.target, r.kind, r.created_at, edges_p[r.kind]["base_ppm"]))
    replied = set()
    for r in posts:
        if r.reply_to_account == "" or r.reply_to_account == r.account:
            continue
        key = (r.account, r.reply_to_account, day_of(r.created_at))
        if key in replied:
            continue
        replied.add(key)
        contribs.append((r.account, r.reply_to_account, "reply", r.created_at, edges_p["reply"]["base_ppm"]))
    pair_sum, pair_recent, pair_kinds = {}, {}, {}
    recent = as_of - p["liability"]["edge_days"] * DAY
    for src, dst, kind, at, base in contribs:
        if src == dst or src in service or dst in service or src not in is_node or dst not in is_node:
            continue
        if root_of(src) == root_of(dst) or src in reset or penalty.get(src, 0) >= PPM:
            continue
        v = base * cv.decay(edges_p[kind]["day_factor_ppm"], D - day_of(at)) // PPM
        if v <= 0:
            continue
        k = (src, dst)
        pair_sum[k] = pair_sum.get(k, 0) + v
        if at >= recent:
            pair_recent[k] = pair_recent.get(k, 0) + v
        pair_kinds.setdefault(k, set()).add("vote" if kind == "legacy_vote" else kind)

    def saturate(s):
        return PPM * s // (PPM + s)

    by_src = {}
    for (src, dst), s in pair_sum.items():
        w = saturate(s)
        if w > 0:
            by_src.setdefault(index[src], []).append((index[src], index[dst], w))
    edges = []
    for lst in by_src.values():
        lst.sort(key=lambda e: (-e[2], e[1]))
        edges += lst[:p["k_out"]]
    edges.sort(key=lambda e: (e[0], e[1]))

    # Own average and transit, from published runs.
    def active_days(a, lo, hi):
        return sum(1 for d in activity.get(a, ()) if lo <= d < hi)

    prior_runs = snap.meta.prior_runs
    own_avg, transit = [0] * len(nodes), [0] * len(nodes)
    for i, a in enumerate(nodes):
        if prior_runs <= 0:
            continue
        span = p["activity_days"]
        fs = first_seen.get(a, 0)
        if fs > 0:
            span = max(1, min(p["activity_days"], D - day_of(fs)))
        share = min(PPM, gdiv(active_days(a, D - p["activity_days"], D) * PPM, span))
        avg = min(U, gdiv(flow_sum.get(a, 0), prior_runs))
        own_avg[i] = gdiv(avg * share, PPM)
        if a not in reset:
            transit[i] = gdiv(gdiv(p["lambda_ppm"] * own_avg[i], PPM) * (PPM - penalty.get(a, 0)), PPM)

    # Proof collateral: min(forge, rent) × curve(age), saturating per root.
    account_proofs = {}
    for r in proofs:
        if r.account in service or r.created_at > as_of:
            continue
        price = p["proofs"].get(r.kind, {"forge": 0, "rent": 0, "curve": "", "day_factor_ppm": 0})
        part = {"kind": r.kind, "value": r.link_value, "state": r.state, "forge": price["forge"], "rent": price["rent"],
                "curve": price["curve"], "age_days": max(0, D - day_of(r.created_at)), "weight_ppm": 0, "contribution": 0,
                "saturated_by": "", "note": ""}
        if r.kind == "domain":
            part["root"] = domain_root(r.link_value, suffixes)
        elif r.kind == "ed25519":
            part["root"] = "key:" + r.link_account
        else:
            part["root"] = r.kind + ":" + r.link_value
            if price.get("assess", "") and r.root != "":
                part["root"] = r.root
        if not counts(r):
            part["note"] = "not counted in this state"
        elif price.get("assess", ""):
            # An assessed root (version 5): its record carries the value.
            part["weight_ppm"] = PPM
            part["note"] = f"assessed {r.assessed} ({price['assess']})"
            part["contribution"] = assessed_contribution(price, r.assessed)
            account_proofs.setdefault(r.account, []).append(part)
            continue
        elif price["curve"] == "ramp":
            part["weight_ppm"] = min(500000, cv.ramp(price["day_factor_ppm"], part["age_days"]))
            part["note"] = "verified age unknown: at most half weight, bounded by the link's age"
        else:
            part["weight_ppm"] = PPM
        part["contribution"] = min(price["forge"], price["rent"]) * part["weight_ppm"] // PPM
        account_proofs.setdefault(r.account, []).append(part)
    # History: days with a post that drew a reply or an up vote from another
    # root with standing in the previous run.
    qualified = {}

    def qualify(post, by):
        if by == "" or by == post.account or by in service or by not in standing or root_of(by) == root_of(post.account):
            return
        qualified.setdefault(post.account, set()).add(day_of(post.created_at))

    for r in posts:
        if r.reply_to != "" and r.reply_to in post_by_id:
            qualify(post_by_id[r.reply_to], r.account)
    for r in current:
        if r.kind == "vote" and r.value == 1 and r.message_id in post_by_id:
            qualify(post_by_id[r.message_id], r.voter)
    h = p["history"]
    for a, days in qualified.items():
        n = min(len(days), h["days_cap"])
        part = {"kind": "history", "value": f"{len(days)} days", "root": "history:" + a, "state": "computed",
                "forge": n * h["day_price"], "rent": n * h["day_price"], "curve": "ramp", "age_days": D - min(days),
                "saturated_by": "", "note": "lagged one run"}
        part["weight_ppm"] = cv.ramp(h["day_factor_ppm"], part["age_days"])
        part["contribution"] = part["forge"] * part["weight_ppm"] // PPM
        account_proofs.setdefault(a, []).append(part)
    proof_total, distinct_roots, non_domain_max = {}, {}, {}
    for a, parts in account_proofs.items():
        parts.sort(key=lambda x: (x["root"], -x["contribution"], x["kind"], x["value"]))
        total = 0
        for i, part in enumerate(parts):
            if i > 0 and parts[i - 1]["root"] == part["root"]:
                best = parts[i - 1]
                part["saturated_by"] = best["saturated_by"] or best["kind"] + ":" + best["value"]
                continue
            total += part["contribution"]
            if part["contribution"] > 0:
                distinct_roots[a] = distinct_roots.get(a, 0) + 1
                if not part["root"].startswith("domain:"):
                    non_domain_max[a] = max(non_domain_max.get(a, 0), part["contribution"])
        proof_total[a] = total

    # Seed sets A (the parameters) and B (the public anchor rule).
    seeds_a = sorted(index[s] for s in p["seeds"] if s in index)
    seeds_a_list = sorted(s for s in p["seeds"] if s in index)
    rule = p["seeds_b"]
    seeds_b, seeds_b_list = [], []
    for i, a in enumerate(nodes):
        fs = first_seen.get(a, 0)
        anchored = distinct_roots.get(a, 0) >= rule["min_roots"] or non_domain_max.get(a, 0) >= max(1, rule["theta_anchor"])
        if (anchored and fs > 0 and fs <= as_of - rule["min_age_days"] * DAY
                and active_days(a, D - rule["of_days"], D) >= rule["active_days"] and penalty.get(a, 0) == 0):
            seeds_b.append(i)
            seeds_b_list.append(a)
    use_b = len(seeds_b) >= rule["min_members"]
    H = sum(1 for a in nodes if active_days(a, D - p["active_days"], D) > 0)
    pool = U * max(H, 1)

    # The flow graph: per-root hubs for roots with two or more nodes.
    groups = {}
    for i, a in enumerate(nodes):
        groups.setdefault(root_of(a), []).append(i)
    hub_labels = sorted(l for l, members in groups.items() if len(members) >= 2)
    hub = [-1] * len(nodes)
    for j, l in enumerate(hub_labels):
        for i in groups[l]:
            hub[i] = j
    graph = {"n": len(nodes), "transit": transit, "hub": hub, "hubs": len(hub_labels), "hub_cap": p["root_cap_shares"] * U,
             "node_cap": U, "steps": p["fill_steps"], "src": [e[0] for e in edges], "dst": [e[1] for e in edges],
             "cap": [p["edge_cap_ppm"] * U * e[2] // 10**12 for e in edges]}
    fa_node, fa_edge, work = run_flow(graph, seeds_a, pool, p["max_work"], 0)
    fb_node, fb_edge = fa_node, fa_edge
    if use_b:
        fb_node, fb_edge, work = run_flow(graph, seeds_b, pool, p["max_work"], work)

    def flow_of(i):
        return min(fa_node[i], fb_node[i]) if use_b else fa_node[i]

    def edge_flow(k):
        return min(fa_edge[k], fb_edge[k]) if use_b else fa_edge[k]

    in_edges = {}
    for k, e in enumerate(edges):
        in_edges.setdefault(e[1], []).append(k)

    # Evidence and liability.
    evidence = detect(p, snap, as_of, D, service, nodes, edges)
    lia = p["liability"]
    penalties = []
    for ev in evidence:
        members = set(ev["members"])
        for m in ev["members"]:
            penalties.append({"account": m, "evidence": ev["id"], "fraction_ppm": PPM, "starts_at": as_of, "ends_at": as_of + lia["penalty_days"] * DAY})
        into = {}
        for (src, dst), s in pair_recent.items():
            if dst in members and src not in members and src not in service:
                into[src] = into.get(src, 0) + s
        for u, s in into.items():
            pen = min(lia["phi_max_ppm"], lia["phi_ppm"] * saturate(s) // PPM)
            if pen > 0:
                penalties.append({"account": u, "evidence": ev["id"], "fraction_ppm": pen, "starts_at": as_of, "ends_at": as_of + lia["penalty_days"] * DAY})
    penalties.sort(key=lambda x: (x["account"], x["evidence"]))
    effective = dict(penalty)
    for pen in penalties:
        effective[pen["account"]] = max(effective.get(pen["account"], 0), pen["fraction_ppm"])

    # Scores: every node and every account with a proof.
    seed_a, seed_b = set(seeds_a_list), set(seeds_b_list) if use_b else set()
    flow_total, scores = {}, []
    for a in sorted(set(nodes) | set(account_proofs)):
        parts = {"proofs": account_proofs.get(a, []), "endorsers": [], "endorsers_total": 0, "down_votes": down_votes.get(a, 0),
                 "penalty_ppm": effective.get(a, 0), "own_avg": 0, "transit": 0, "seed": "", "reset": a in reset}
        sc = {"account": a, "root": root_of(a), "proof_collateral": proof_total.get(a, 0), "flow_a": 0, "flow_b": None, "flow": 0, "parts": parts}
        if a in index:
            i = index[a]
            sc["flow_a"] = fa_node[i]
            if use_b:
                sc["flow_b"] = fb_node[i]
            sc["flow"] = flow_of(i)
            parts["own_avg"], parts["transit"] = own_avg[i], transit[i]
            endorsers = []
            for k in in_edges.get(i, []):
                src = nodes[edges[k][0]]
                endorsers.append({"agent": src, "kinds": sorted(pair_kinds[(src, a)]), "weight_ppm": edges[k][2], "flow": edge_flow(k)})
            endorsers.sort(key=lambda x: (-x["flow"], -x["weight_ppm"], x["agent"]))
            parts["endorsers_total"] = len(endorsers)
            parts["endorsers"] = endorsers[:20]
        parts["seed"] = ("a" if a in seed_a else "") + ("b" if a in seed_b else "")
        flow_total[a] = sc["flow"]
        sc["collateral"] = sc["proof_collateral"] + sc["flow"] * p["endorsement_unit_price"]
        if sc["flow"] > 0 and sc["flow"] >= p["theta_trusted"]:
            sc["tier"] = 1
        elif sc["proof_collateral"] > 0 and sc["proof_collateral"] >= p["theta_proven"]:
            sc["tier"] = 2
        else:
            sc["tier"] = 3
        sc["weight_ppm"] = gdiv((PPM + min(p["weight_cap_ppm"], sc["collateral"] * p["weight_per_unit_ppm"])) * (PPM - effective.get(a, 0)), PPM)
        scores.append(sc)

    standing_summary = None
    if "standing" in p:
        parts_by, standing_summary, extra = compute_standing(
            p, snap, as_of, D, service, root_of, reset, effective, posts, current, account_proofs,
            sorted(set(nodes) | set(account_proofs)), {sc["account"]: sc["tier"] for sc in scores},
            {sc["account"]: sc["collateral"] for sc in scores})
        for sc in scores:
            sc["parts"]["standing"] = parts_by[sc["account"]]
        # An account whose only evidence is a standing input is scored too.
        for a in extra:
            pen = effective.get(a, 0)
            scores.append({"account": a, "root": root_of(a), "proof_collateral": 0, "flow_a": 0, "flow_b": None, "flow": 0,
                           "collateral": 0, "tier": 3, "weight_ppm": PPM * (PPM - pen) // PPM,
                           "parts": {"proofs": [], "endorsers": [], "endorsers_total": 0, "down_votes": down_votes.get(a, 0),
                                     "penalty_ppm": pen, "own_avg": 0, "transit": 0, "seed": "", "reset": a in reset,
                                     "standing": parts_by[a]}})
        scores.sort(key=lambda sc: sc["account"])

    sponsorships, dividends = sponsor(p, snap, as_of, service, first_seen, reset, index, own_avg, root_of, pair_sum, flow_total,
                                      lambda x: [] if x not in index else [(nodes[edges[k][0]], edge_flow(k)) for k in in_edges.get(index[x], [])])

    max_transit = max([transit[i] for i, a in enumerate(nodes) if a not in seed_a and a not in seed_b] or [0])
    body = canonical(p)
    out = {
        "schema": 1, "as_of": as_of, "params_version": snap.params_version,
        "params_sha256": hashlib.sha256(body.encode()).hexdigest(),
        "inputs": {"events_seq": snap.meta.events_seq, "endorsements_seq": snap.meta.endorsements_seq, "ledger_seq": snap.meta.ledger_seq,
                   "prior_runs": prior_runs, "accounts": len(snap.accounts), "posts": len(posts), "endorsements": len(ends),
                   "proofs": len(snap.proofs), "transfers": len(snap.transfers)},
        "nodes": len(nodes), "edges": len(edges), "pool_units": pool, "active_accounts": H,
        "seeds_a": seeds_a_list, "seeds_b": seeds_b_list, "seeds_b_used": use_b,
        "capture_bound": {"unit_per_share": U, "edge_cap_units": p["edge_cap_ppm"] * U // PPM, "lambda_ppm": p["lambda_ppm"],
                          "max_transit_units": max_transit, "pool_units": pool,
                          "statement": "Whatever the number of sybils, a region behind k attack edges receives at most k x edge_cap_units flow units, and at most max_transit_units through any one non-seed endorser."},
        "scores": scores, "evidence": evidence, "penalties": penalties, "sponsorships": sponsorships, "dividends": dividends,
    }
    if standing_summary is not None:
        out["standing"] = standing_summary
    return out


# ---------------------------------------------------------------------------
# Standing (RFC0015 §3, trust parameter version 2)

MASS_PER_CENT = 1000  # the run's mass unit: a thousandth of a cent
INT64_MAX = 2**63 - 1


def mul_div(a: int, b: int, c: int) -> int:
    """floor(a × b / c) for non-negative a, b and positive c; a quotient past
    int64 saturates, as the reference's 128-bit mulDiv does."""
    if a <= 0 or b <= 0 or c <= 0:
        return 0
    return min(a * b // c, INT64_MAX)


def vote_weight_ppm(cents: int, v0: int, c_ref: int, floor: int = 0) -> int:
    """v(s) in ppm: 0 for C = 0 or C below the floor (v_floor_cents), else
    v0 + (1 − v0) × √min(1, C / C_ref)."""
    if cents <= 0 or c_ref <= 0 or cents < floor:
        return 0
    frac = PPM if cents >= c_ref else mul_div(cents, PPM, c_ref)
    return v0 + mul_div(PPM - v0, math.isqrt(frac * PPM), PPM)


def share_weight_ppm(cents: int, p) -> int:
    return PPM + min(p["weight_cap_ppm"], max(0, cents) * p["weight_per_unit_ppm"])


def band(cents: int, st) -> int:
    if cents >= st["theta1_cents"]:
        return 1
    if cents >= st["theta2_cents"]:
        return 2
    return 3


def compute_standing(p, snap, as_of, D, service, root_of, reset, penalty, posts, current, account_proofs, scored, tiers, collateral):
    """Seed mass on priced entities (split between their controllers), credit
    spent (at cost, decayed), and the arbiter's seed list;
    endorse edges (up votes, vouches, work.accept, verified witnesses) and
    oppose edges (down votes), one weight per act, one half-life, saturating
    per pair and polarity; personalized PageRank from the seeds; oppose
    shares subtracted at the target; penalties scale outflow and standing.
    Rule 2: an act weighs its kind's weight (a vouch the weight its author
    chose, capped), saturating per pair, polarity and kind at twice one act;
    a node passes pass × W / (K + W) along its edges and returns the rest to
    the seeds; standing is c, not rescaled."""
    st = p["standing"]
    rule, v_floor = st.get("rule", 0), st.get("v_floor_cents", 0)
    spend_cap, funded_days = st.get("spend_cap_cents", 0), st.get("funded_days", 0)
    cv = Curves()
    ws = as_of - p["window_days"] * DAY
    inputs = {"vote": 0, "vouch": 0, "work_accept": 0, "witness": 0, "down_vote": 0, "spend": 0}

    seeds = {}  # account -> [(root, kind, source, state, mass)]
    claimants = {}
    bests = []
    for a in sorted(account_proofs):
        for part in account_proofs[a]:
            if part["saturated_by"] != "" or part["kind"] == "history":
                continue
            bests.append((a, part))
            if part["contribution"] > 0:
                claimants[part["root"]] = claimants.get(part["root"], 0) + 1
    # Rule 1: a domain is priced by its registration age when known (in
    # full), else by the link's age (at most half), and the state says which.
    registered = {}
    if rule >= 1:
        for r in snap.proofs:
            if r.kind != "domain" or r.registered_at <= 0 or r.registered_at > as_of:
                continue
            k = (r.account, r.link_value)
            if k not in registered or r.registered_at < registered[k]:
                registered[k] = r.registered_at
    for a, part in bests:
        contribution, state = part["contribution"], part["state"]
        if rule >= 1 and part["kind"] == "domain" and part["note"] != "not counted in this state":
            if (a, part["value"]) in registered:
                price = p["proofs"]["domain"]
                age = max(0, D - day_of(registered[(a, part["value"])]))
                contribution = min(price["forge"], price["rent"]) * cv.ramp(price["day_factor_ppm"], age) // PPM
                state += " (registration age)"
            else:
                state += " (link age: registration date unknown)"
        n = claimants.get(part["root"], 0)
        mass = contribution * MASS_PER_CENT // n if n > 0 and contribution > 0 else 0
        state += " (not counted)" if part["note"] == "not counted in this state" else ""
        seeds.setdefault(a, []).append((part["root"], "imported", part["kind"], state, mass))
    # Rule 1: spend paid to oneself (the payee shares the spender's root, or
    # either funded the other within funded_days) is not seed.
    self_dealt = None
    funded = set()
    if rule >= 1:
        inputs["spend_self_dealt"] = 0
        lo = as_of - funded_days * DAY
        for r in snap.transfers:
            t_from = r["from"] if "from" in r else ""
            if lo <= r.created_at < as_of and t_from != "" and r.to != "" and t_from != r.to and r.amount > 0:
                funded.add((t_from, r.to))
                funded.add((r.to, t_from))
        suffixes = set(p["domain_suffixes"])

        def self_dealt(r):
            root = root_of(r.account)
            if r.to != "" and (r.to == r.account or root_of(r.to) == root or (r.account, r.to) in funded):
                return True
            return r.link_value != "" and root_of(domain_root(r.link_value, suffixes)) == root
    spend = {}
    for r in sorted(snap.spends, key=record_key):
        if r.account == "" or r.account in service or r.day >= D or r.amount <= 0:
            continue
        if self_dealt is not None and self_dealt(r):
            inputs["spend_self_dealt"] += 1
            continue
        inputs["spend"] += 1
        spend[r.account] = spend.get(r.account, 0) + mul_div(min(r.amount, 10**15), cv.decay(st["day_factor_ppm"], D - r.day) * MASS_PER_CENT,
                                                             PPM * st["credits_per_cent"])
    for a, m in spend.items():
        if spend_cap > 0:
            m = min(m, spend_cap * MASS_PER_CENT)
        seeds.setdefault(a, []).append(("spend:" + a, "earned", "spend", "computed", m))
    for s in p["seeds"]:
        if s not in service:
            seeds.setdefault(s, []).append(("arbiter", "earned", "arbiter_seed", "seed list", st["arbiter_seed_cents"] * MASS_PER_CENT))

    acts = []
    for r in current:
        if r.created_at < ws or r.target == "":
            continue
        if r.kind in ("vote", "vouch") and r.value == 1:
            acts.append((r.voter, r.target, r.kind, r.created_at, False, r.weight, r.message_id))
        elif r.kind == "vote" and r.value == -1:
            acts.append((r.voter, r.target, "down_vote", r.created_at, True, 0, r.message_id))
    for r in sorted(snap.acts, key=record_key):
        if r.created_at >= as_of or r.created_at < ws or r.kind not in ("work_accept", "witness"):
            continue
        # A failed witness verdict (value -1) is read from rule 3 only: a
        # position against the witnessed claim, no edge.
        if r.value < 0 and (rule < 3 or r.kind != "witness"):
            continue
        acts.append((r["from"] if "from" in r else "", r.to, r.kind, r.created_at, r.value < 0, 0, r.id))

    def act_weight(kind, chosen):
        if kind == "vouch" and chosen > 0:
            return min(chosen, st["vouch_weight_max"])
        return st["edge_weights"][kind]
    pair_sum = {}
    kind_sum, kind_weight = {}, {}
    staked = []
    if rule >= 3:
        inputs["witness_failed"] = 0
    for src, dst, kind, at, oppose, chosen, item in acts:
        if src == "" or dst == "" or src == dst or src in service or dst in service or src in reset:
            continue
        if root_of(src) == root_of(dst):
            continue
        v = cv.decay(st["day_factor_ppm"], D - day_of(at))
        if v <= 0:
            continue
        if kind == "witness" and oppose:
            inputs["witness_failed"] += 1
        else:
            inputs[kind] += 1
        if rule >= 3:
            staked.append((src, dst, kind, item, at, oppose, act_weight(kind, chosen) * v))
        if rule >= 2:
            k = (src, dst, oppose, kind)
            kind_sum[k] = kind_sum.get(k, 0) + v
            kind_weight[k] = max(kind_weight.get(k, 0), act_weight(kind, chosen))
            continue
        pair_sum[(src, dst, oppose)] = pair_sum.get((src, dst, oppose), 0) + v
    # Rule 2: each kind counts w × 2s / (1 + s), summed per pair and polarity.
    for k, total in kind_sum.items():
        w = kind_weight[k] * mul_div(2 * PPM, total, PPM + total)
        if w > 0:
            pair_sum[k[:3]] = pair_sum.get(k[:3], 0) + w

    nodes = sorted(set(seeds) | {k[0] for k in pair_sum} | {k[1] for k in pair_sum} | set(scored))
    index = {a: i for i, a in enumerate(nodes)}
    n = len(nodes)
    seed = [sum(r[4] for r in seeds.get(a, [])) for a in nodes]
    S = sum(seed)
    outs = [[] for _ in range(n)]
    wsum = [0] * n
    for (src, dst, oppose), total in pair_sum.items():
        w = total if rule >= 2 else PPM * total // (PPM + total)
        if w > 0:
            outs[index[src]].append((index[dst], w, oppose))
            wsum[index[src]] += w
    for lst in outs:
        lst.sort(key=lambda e: (e[0], e[2]))
    pen = [min(PPM, penalty.get(a, 0)) for a in nodes]

    stake_out = None
    if rule >= 3:
        stake_out = run_stakes(st, as_of, ws, nodes, seed, pen, staked,
                               lambda a, b: a != b and root_of(a) != root_of(b) and (a, b) not in funded)

    c = list(seed)
    keep = st.get("keep_weight", 0) * PPM
    restart = [x - mul_div(x, st["pass_ppm"], PPM) for x in seed]
    opposed = [0] * n
    for _ in range(st["iterations"] if rule < 3 else 0):
        nxt = list(restart)
        opposed = [0] * n
        back = 0
        for u in range(n):
            pas = mul_div(c[u], st["pass_ppm"], PPM)
            held = mul_div(pas, pen[u], PPM)
            pas -= held
            back += held
            if wsum[u] == 0:
                if rule >= 1:
                    back += pas  # dangling: returns to the seeds
                else:
                    nxt[u] += pas
                continue
            if rule >= 2:
                out = mul_div(pas, wsum[u], wsum[u] + keep)
                back += pas - out  # kept: returns to the seeds
                pas = out
            sent = 0
            for dst, w, oppose in outs[u]:
                share = mul_div(pas, w, wsum[u])
                sent += share
                if oppose:
                    opposed[dst] += share
                    back += share
                    continue
                nxt[dst] += share
            nxt[u] += pas - sent
        for i in range(n):
            if S > 0 and seed[i] > 0:
                nxt[i] += mul_div(back, seed[i], S)
        c = nxt

    seasoned = {r.account for r in posts if r.created_at <= as_of - DAY}
    scored_set = set(scored)
    v0, c_ref = st["v0_ppm"], st["c_ref_cents"]

    def vw(cents):
        return vote_weight_ppm(cents, v0, c_ref, v_floor)
    entities = {}
    for a in nodes:
        for root, _, _, _, mass in seeds.get(a, []):
            typ = root.split(":", 1)[0]
            e = entities.setdefault(typ, {"controls": 0, "seed_cents": 0})
            e["controls"] += 1
            e["seed_cents"] += mass // MASS_PER_CENT
    summary = {
        "mode": st["mode"], "seed_cents": S // MASS_PER_CENT, "inputs": inputs, "bands": {"1": 0, "2": 0, "3": 0},
        "would_be": {"allowance_tier": {"raised": 0, "lowered": 0, "same": 0},
                     "share_weight": {"raised": 0, "added_ppm": 0, "max_added_ppm": 0},
                     "vote_weight": {"zero": 0, "partial": 0, "full": 0, "votes": 0, "votes_weight_ppm": 0, "votes_floored_ppm": 0,
                                     "admitted_unseasoned": 0},
                     "inbox_known": {"today": 0, "would_be": 0, "raised": 0}},
        "anonymous": {"cents": st["anon_seed_cents"], "vote_weight_ppm": vw(st["anon_seed_cents"]),
                      "share_weight_ppm": share_weight_ppm(st["anon_seed_cents"], p)},
        "entities": entities, "largest_moves": [], "accounts": 0, "nonzero": 0,
    }
    wb = summary["would_be"]
    parts, extra, moves, total = {}, [], [], 0
    if rule >= 3:
        c = stake_out["c"]
    for i, a in enumerate(nodes):
        raw, opp = c[i], opposed[i]
        if rule >= 3:
            raw = stake_out["raw"][i]  # before the penalty; c[i] is after it
        if rule == 1:  # reported as c / (1 − pass); rule 2 reports c
            raw, opp = mul_div(raw, PPM, PPM - st["pass_ppm"]), mul_div(opp, PPM, PPM - st["pass_ppm"])
        cents = mul_div(max(0, raw - opp), PPM - pen[i], PPM) // MASS_PER_CENT
        if rule >= 3:
            cents = c[i] // MASS_PER_CENT
        part = {"cents": cents, "raw_cents": raw // MASS_PER_CENT, "opposed_cents": opp // MASS_PER_CENT, "penalty_ppm": pen[i],
                "seed_cents": seed[i] // MASS_PER_CENT, "received_cents": max(0, raw - seed[i]) // MASS_PER_CENT, "band": band(cents, st),
                "vote_weight_ppm": vw(cents), "share_weight_ppm": share_weight_ppm(cents, p), "breakdown": []}
        own = min(raw, seed[i])
        for root, kind, source, state, mass in seeds.get(a, []):
            contribution = mul_div(own, mass, seed[i]) // MASS_PER_CENT if seed[i] > 0 else 0
            part["breakdown"].append({"root": root, "kind": kind, "source": source, "state": state, "seed_cents": mass // MASS_PER_CENT,
                                      "contribution": contribution})
        if raw > seed[i] and rule >= 3:
            # What it holds above its seed: what its judgement earned
            # (settled stakes), and what endorsers moved to it.
            above = raw - seed[i]
            judged = min(above, max(0, stake_out["judged"][i]))
            if above - judged >= MASS_PER_CENT:
                part["breakdown"].append({"root": "endorsements", "kind": "earned", "source": "edges", "state": "computed", "seed_cents": 0,
                                          "contribution": (above - judged) // MASS_PER_CENT})
            if judged >= MASS_PER_CENT:
                part["breakdown"].append({"root": "judgement", "kind": "earned", "source": "stakes", "state": "computed", "seed_cents": 0,
                                          "contribution": judged // MASS_PER_CENT})
        elif raw > seed[i]:
            part["breakdown"].append({"root": "endorsements", "kind": "earned", "source": "edges", "state": "computed", "seed_cents": 0,
                                      "contribution": (raw - seed[i]) // MASS_PER_CENT})
        part["breakdown"].sort(key=lambda b: (-b["contribution"], -b["seed_cents"], b["root"]))
        parts[a] = part
        if a not in scored_set:
            if cents == 0 and seed[i] == 0:
                continue
            extra.append(a)
        total += cents
        summary["accounts"] += 1
        if cents > 0:
            summary["nonzero"] += 1
        summary["bands"][str(part["band"])] += 1
        tier = tiers.get(a, 3)
        if part["band"] < tier:
            wb["allowance_tier"]["raised"] += 1
        elif part["band"] > tier:
            wb["allowance_tier"]["lowered"] += 1
        else:
            wb["allowance_tier"]["same"] += 1
        added = part["share_weight_ppm"] - PPM
        if added > 0:
            wb["share_weight"]["raised"] += 1
            wb["share_weight"]["added_ppm"] += added
            wb["share_weight"]["max_added_ppm"] = max(wb["share_weight"]["max_added_ppm"], added)
        v = part["vote_weight_ppm"]
        wb["vote_weight"]["zero" if v == 0 else "partial" if v < PPM else "full"] += 1
        if a not in seasoned and v >= 500000:
            wb["vote_weight"]["admitted_unseasoned"] += 1
        today = collateral.get(a, 0) >= p["theta_proven"] and collateral.get(a, 0) > 0
        would = cents >= st["theta2_cents"]
        if today:
            wb["inbox_known"]["today"] += 1
        if would:
            wb["inbox_known"]["would_be"] += 1
            if not today:
                wb["inbox_known"]["raised"] += 1
        moves.append({"account": a, "cents": cents, "band": part["band"], "tier": tier, "share_weight_ppm": part["share_weight_ppm"],
                      "vote_weight_ppm": v, "seasoned": a in seasoned})
    summary["standing_cents"] = total
    for r in current:
        if r.kind != "vote" or r.created_at < ws or r.value not in (1, -1):
            continue
        wb["vote_weight"]["votes"] += 1
        cents = parts[r.voter]["cents"] if r.voter in parts else 0
        v = vw(cents)
        wb["vote_weight"]["votes_weight_ppm"] += v
        wb["vote_weight"]["votes_floored_ppm"] += max(PPM, v)
    moves.sort(key=lambda m: (-m["share_weight_ppm"], -m["cents"], m["account"]))
    for m in moves:
        if len(summary["largest_moves"]) == 10 or m["share_weight_ppm"] <= PPM:
            break
        summary["largest_moves"].append(m)
    return parts, summary, sorted(extra)


def _score(R: int, P: int) -> int:
    """(R − P) / (R + P) in ppm, P ≥ 1."""
    if R >= P:
        return mul_div(R - P, PPM, R + P)
    return -mul_div(P - R, PPM, R + P)


def _lower_median(xs: list) -> int:
    if not xs:
        return 0
    xs = sorted(xs)
    return xs[(len(xs) - 1) // 2]


def run_stakes(st, as_of, ws, nodes, seed, pen, acts, indep):
    """Rule 3: endorsements are stakes. Each act commits stake_ppm × weight ×
    decay of its author's standing (scaled down together above
    stake_budget_ppm). A vouch, an accepted work item and a verified witness
    move it to the target; a vote on a post, a witness verdict on a claim and
    a vouch or accept on its target are positions. A post opens at its
    author's median reception (the median over all posts until the author
    has prior_min_posts with any), priced at the larger of that and the stake
    already on it; a claim opens at nothing; an agent at its trajectory. R is
    the stake of independent accounts (another root, no transfer within
    funded_days): on the post, on the claim's side less against it, moved to
    the agent after the act. r = (R − P) / (R + P); within a pot (an author's
    posts, a claim, an agent) losers pay up to |r|/2 of their stake to
    winners, pro rata; a penalised agent's vouchers score −1 and lose half
    their stake times the penalty. Standing is the fixed point of seed +
    moved in − moved out + settled, iterated from the seed."""
    n = len(nodes)
    index = {a: i for i, a in enumerate(nodes)}
    acts = [a for a in acts if a[0] in index and a[1] in index and a[6] > 0]
    acts.sort(key=lambda a: (a[4], a[0], a[1], a[2], a[3], a[5]))
    m = len(acts)
    src = [index[a[0]] for a in acts]
    dst = [index[a[1]] for a in acts]
    transfer = [False] * m
    obj_of = [""] * m
    load = [0] * n
    objects, transfers_in, post_author = {}, {}, {}
    positions = 0
    for x, (s_, d_, kind, item, at, against, ld) in enumerate(acts):
        if kind in ("vouch", "work_accept"):
            transfer[x], obj_of[x] = True, "g\x00" + d_
        elif kind == "witness" and not against:
            transfer[x] = True
            if item != "":
                obj_of[x] = "c\x00" + d_ + "\x00" + item
        elif kind == "witness":
            if item != "":
                obj_of[x] = "c\x00" + d_ + "\x00" + item
        elif kind == "vote" and item != "":
            obj_of[x] = "p\x00" + d_ + "\x00" + item
            post_author[obj_of[x]] = dst[x]
        if transfer[x]:
            load[src[x]] += ld
            transfers_in.setdefault(dst[x], []).append(x)
        if obj_of[x][:1] in ("p", "c"):
            load[src[x]] += ld
        if obj_of[x] != "":
            objects.setdefault(obj_of[x], []).append(x)
            positions += 1
    scale = []
    for i in range(n):
        share = mul_div(st["stake_ppm"], load[i], PPM)
        scale.append(mul_div(st["stake_budget_ppm"], PPM, share) if share > st["stake_budget_ppm"] else PPM)
    keys = sorted(objects)
    agents = sorted(transfers_in)
    eff = [mul_div(s, PPM - pen[i], PPM) for i, s in enumerate(seed)]
    S = sum(eff)
    window = max(1, as_of - ws)
    c = list(seed)
    raw = [0] * n
    judged = [0] * n
    sig = [0] * m
    r = [0] * m
    on = [False] * m
    for _ in range(st["iterations"]):
        nxt = list(seed)
        judged = [0] * n
        for x, a in enumerate(acts):
            sig[x] = mul_div(mul_div(c[src[x]], st["stake_ppm"], PPM), mul_div(a[6], scale[src[x]], PPM), PPM)
            if transfer[x]:
                nxt[src[x]] -= sig[x]
                nxt[dst[x]] += sig[x]
        reception, everything = {}, []
        for k in keys:
            if k[0] != "p":
                continue
            mass = sum(sig[x] for x in objects[k])
            if mass > 0:
                reception.setdefault(post_author[k], []).append(mass)
                everything.append(mass)
        unknown = _lower_median(everything)
        totals = [t for t in (sum(sig[y] for y in transfers_in[d]) for d in agents) if t > 0]
        agent_median = _lower_median(totals)
        for k in keys:
            xs = objects[k]
            if k[0] == "p":
                rec = reception.get(post_author[k], [])
                p0 = _lower_median(rec) if len(rec) >= st["prior_min_posts"] else unknown
                for x in xs:
                    R = B = 0
                    for y in xs:
                        if acts[y][4] < acts[x][4]:
                            B += sig[y]
                        if y != x and indep(acts[x][0], acts[y][0]):
                            R += sig[y]
                    r[x], on[x] = _score(R, max(p0, B, 1)), True
            elif k[0] == "c":
                for x in xs:
                    same = other = B = 0
                    for y in xs:
                        if acts[y][5] == acts[x][5] and acts[y][4] < acts[x][4]:
                            B += sig[y]
                        if y == x or not indep(acts[x][0], acts[y][0]):
                            continue
                        if acts[y][5] == acts[x][5]:
                            same += sig[y]
                        else:
                            other += sig[y]
                    on[x] = same + other > 0
                    r[x] = _score(max(0, same - other), max(B, 1))
            else:
                for x in xs:
                    R = before = 0
                    for y in transfers_in[dst[x]]:
                        if acts[y][4] < acts[x][4]:
                            before += sig[y]
                        elif acts[y][4] > acts[x][4] and indep(acts[x][0], acts[y][0]):
                            R += sig[y]
                    left = max(0, as_of - acts[x][4])
                    P = mul_div(before, left, max(1, acts[x][4] - ws)) if before > 0 else mul_div(agent_median, left, window)
                    r[x], on[x] = _score(R, max(P, 1)), True
                    if pen[dst[x]] > 0:
                        r[x] = -PPM
        pots = {}
        for k in keys:
            pot = "a\x00" + acts[objects[k][0]][1] if k[0] == "p" else k
            pots.setdefault(pot, []).extend(objects[k])
        back = 0
        for pk in sorted(pots):
            xs = pots[pk]
            L = sum(mul_div(sig[x], -r[x], 2 * PPM) for x in xs if on[x] and r[x] < 0)
            G = sum(mul_div(sig[x], r[x], 2 * PPM) for x in xs if on[x] and r[x] > 0)
            paid = min(L, G)
            taken = given = 0
            if paid > 0:
                for x in xs:
                    if on[x] and r[x] < 0:
                        t = mul_div(mul_div(sig[x], -r[x], 2 * PPM), paid, L)
                        taken += t
                        judged[src[x]] -= t
                for x in xs:
                    if on[x] and r[x] > 0:
                        g = mul_div(mul_div(sig[x], r[x], 2 * PPM), taken, G)
                        given += g
                        judged[src[x]] += g
            back += taken - given
            if pk[0] == "g":
                for x in xs:
                    burn = mul_div(sig[x], pen[dst[x]], 2 * PPM)
                    if burn > 0:
                        judged[src[x]] -= burn
                        back += burn
        deficit = 0
        removed = [0] * n
        for i in range(n):
            nxt[i] += judged[i]
            removed[i] = mul_div(max(0, nxt[i]), pen[i], PPM)
            nxt[i] -= removed[i]
            back += removed[i]
            if nxt[i] < 0:
                deficit -= nxt[i]
                nxt[i] = 0
        back = max(0, back - deficit)
        for i in range(n):
            if S > 0 and eff[i] > 0:
                nxt[i] += mul_div(back, eff[i], S)
            raw[i] = nxt[i] + removed[i]
        c = nxt
    return {"c": c, "raw": raw, "judged": judged, "positions": positions}


def sponsor(p, snap, as_of, service, first_seen, reset, index, own_avg, root_of, pair_sum, flow_total, inflow):
    """A vouch with sponsor:true within the invitee's first window_days (the
    earliest wins, within the sponsor's daily slots) is a sponsorship. A new
    high of the invitee's independent inflow (edges from endorsers outside both
    roots and not endorsed by the sponsor) earns dividend_ppm of the rise,
    within dividend_days and daily_cap."""
    U, sp = p["unit_per_share"], p["sponsor"]
    prev = {}
    for r in snap.sponsorships:
        prev[r.invitee] = r
    vouches = sorted((r for r in snap.endorsements if r.kind == "vouch" and r.sponsor and r.value == 1 and r.created_at < as_of
                      and r.voter != r.target and r.voter != "" and r.target != "" and r.voter not in service and r.target not in service),
                     key=lambda r: r.seq)
    used, chosen = {}, {}
    for r in vouches:
        fs = first_seen.get(r.target, 0)
        if fs == 0 or r.created_at > fs + sp["window_days"] * DAY or root_of(r.voter) == root_of(r.target):
            continue
        if r.target in chosen:
            continue
        own = own_avg[index[r.voter]] if r.voter in index else 0
        slots = 0 if r.voter in reset else (2 * sp["slots_per_share"] * min(U, own) + U) // (2 * U)
        key = (r.voter, day_of(r.created_at))
        if used.get(key, 0) >= slots:
            continue
        used[key] = used.get(key, 0) + 1
        chosen[r.target] = r
    ships, divs, paid = [], [], {}
    for x in sorted(chosen):
        r = chosen[x]
        s = r.voter
        old = prev.get(x)
        hw = old.high_water if old is not None and old.sponsor_account == s else 0
        indep = 0
        for agent, flow in inflow(x):
            if agent == s or root_of(agent) == root_of(s) or root_of(agent) == root_of(x) or pair_sum.get((s, agent), 0) > 0:
                continue
            indep += flow
        indep = min(indep, flow_total.get(x, 0))
        ends = r.created_at + sp["dividend_days"] * DAY
        if as_of < ends and indep > hw:
            units = min(gdiv(sp["dividend_ppm"] * (indep - hw), PPM), sp["daily_cap"] - paid.get(s, 0))
            if units > 0:
                paid[s] = paid.get(s, 0) + units
                divs.append({"sponsor": s, "invitee": x, "units": units})
        ships.append({"invitee": x, "sponsor": s, "record_seq": r.seq, "created_at": r.created_at, "ends_at": ends, "high_water": max(hw, indep)})
    return ships, divs


# ---------------------------------------------------------------------------
# RFC 0021 (parameter version 8, snapshot schema 2): the one trust graph.
#
# Restated from docs/rfcs/0021-trust-graph-simplified.md and the reference's
# internal/trust (compute.go, graph.go, judgements.go, detect.go), step for
# step, and checked against testdata/golden_unified_*. Amounts are
# millicents (MC per cent); divisions of non-negative values floor, of
# possibly negative ones truncate toward zero (gdiv), as Go's do.

MC = 1000
SNAPSHOT_SCHEMA_V2 = 2
UNIFIED_VERSION = 8
PASS_VERSION = 10
BREAKER_VERSION = 11
FLOOR_ONCE_VERSION = 12  # C492: a capped row's fallback counts once per (kind, node root); rule only, body as 11
DOMAIN_FLOOR_ONCE_VERSION = 13  # C515: a fallback-priced domain's floor counts once per node root; rule only, body as 12
BREAKER_REASONS = {"agent.rotate", "dormant", "identity.link", "identity.unlink", "spike"}

RECORD_FIELDS_V2 = [
    ("type", ""), ("schema", 0), ("as_of", 0), ("pause_new_keys_since", 0), ("events_seq", 0), ("endorsements_seq", 0), ("ledger_seq", 0),
    ("version", 0), ("body", None), ("id", ""), ("kind", ""), ("account", ""), ("created_at", 0), ("value", 0), ("state", ""), ("target", ""),
    ("first_seen", 0), ("reply_to", ""), ("reply_to_account", ""), ("seq", 0), ("voter", ""), ("message_id", ""), ("link_value", ""),
    ("checked_at", 0), ("link_account", ""), ("registered_at", 0), ("root", ""), ("assessed", 0), ("rank", 0), ("started_at", 0),
    ("trust_until", 0), ("from", ""), ("to", ""), ("amount", 0), ("day", 0), ("claimed", 0), ("spent", 0), ("evidence", ""),
    ("fraction_ppm", 0), ("ends_at", 0), ("time", 0), ("last_active", 0), ("direct", 0), ("standing", 0), ("backed", 0),
]
FIELD_ZERO_V2 = dict(RECORD_FIELDS_V2)
RECORD_TYPES_V2 = {"meta", "params", "account", "post", "endorsement", "proof", "breaker", "transfer", "claim", "payment", "edge",
                   "review", "owner", "penalty", "burn", "liability", "lift", "carry"}
PARAM_KEYS_V2 = {
    "schema", "collateral_unit", "grace_days", "dormant_half_life_days", "dormant_day_factor_ppm", "half_life_days", "day_factor_ppm",
    "evidence_weight_ppm", "unit_cents", "min_judges", "theta2_cents", "v_floor_cents", "c_ref_cents", "node_cap_cents", "v0_ppm",
    "proofs", "domain_suffixes", "proof_fresh_days", "day_price_cents", "time_cap_cents", "coarse_x", "act_evidence", "detectors",
    "penalty", "window_days", "n_max", "max_work", "max_seconds",
}
PARAM_SECTIONS_V2 = {
    "detectors": {"version", "funnel_k", "funnel_days", "funnel_spend_ppm", "ring_min", "ring_inside_ppm"},
    "penalty": {"base_days", "duration_factor", "backer_factor", "escalation_days", "backer_edge_days", "max_level"},
    "evidence_weight_ppm": {"free_use", "observed", "opinion", "paid_use", "work"},
    "act_evidence": {"vote", "vouch", "witness", "work_accept"},
}
TRIGGERS = {"ring", "funnel", "shared_wallet", "moderation", "override"}
LOG2_TEN = 3566893132
INT64_MAX_V2 = 2**63 - 1


class Rec2(dict):
    """A schema 2 input record; absent fields read as their zero value."""

    def __getattr__(self, name):
        if name == "from_":
            return self.get("from", "")
        return self.get(name, FIELD_ZERO_V2.get(name))


def record_key_v2(r: dict) -> str:
    parts = []
    for name, zero in RECORD_FIELDS_V2:
        value = r.get(name, zero)
        if name != "type" and (value == zero or value is None):
            continue
        if isinstance(value, int):
            encoded = str(value)
        elif isinstance(value, str):
            encoded = _go_quote(value)
        else:
            encoded = json.dumps(value, separators=(",", ":"), ensure_ascii=False)
        parts.append(_go_quote(name) + ":" + encoded)
    return "{" + ",".join(parts) + "}"


def sort_v2(records):
    return sorted(records, key=record_key_v2)


def plain_v2(r: dict) -> dict:
    """A record as Go marshals it: its non-zero fields."""
    return {k: v for k, v in r.items() if k == "type" or (v != FIELD_ZERO_V2.get(k) and v is not None)}


class SnapshotV2:
    def __init__(self):
        self.meta = Rec2()
        self.params = None
        self.params_version = 0
        self.lists = {t: [] for t in RECORD_TYPES_V2 - {"meta", "params"}}

    def of(self, kind):
        return self.lists[kind]


def check_params_v2(body: dict, version: int) -> None:
    if version < UNIFIED_VERSION:
        raise InputError(f"params: version {version} is not a schema 2 version")
    # pass_share_ppm is version 10's (C336), omitted when 0;
    # breaker_trust_days version 11's (C338), omitted when empty.
    if not isinstance(body, dict) or set(body) - {"pass_share_ppm", "breaker_trust_days"} != PARAM_KEYS_V2:
        raise InputError(f"params body: fields must be exactly {sorted(PARAM_KEYS_V2)}, pass_share_ppm from version {PASS_VERSION} "
                         f"and breaker_trust_days from version {BREAKER_VERSION}")
    if "pass_share_ppm" in body and (version < PASS_VERSION or not 0 < body["pass_share_ppm"] <= PPM):
        raise InputError(f"params: pass_share_ppm is version {PASS_VERSION}'s, 1–{PPM}")
    if "breaker_trust_days" in body:
        days = body["breaker_trust_days"]
        if version < BREAKER_VERSION or not isinstance(days, dict) or not days or not set(days) <= BREAKER_REASONS \
                or any(isinstance(d, bool) or not isinstance(d, int) or not 0 <= d <= 365 for d in days.values()):
            raise InputError(f"params: breaker_trust_days is version {BREAKER_VERSION}'s, 0–365 days for each of {sorted(BREAKER_REASONS)}")
    for section, keys in PARAM_SECTIONS_V2.items():
        if not isinstance(body[section], dict) or set(body[section]) != keys:
            raise InputError(f"params {section}: fields must be exactly {sorted(keys)}")
    if body["schema"] != 2 or body["collateral_unit"] != "usd_cent":
        raise InputError("params: schema 2 in usd_cent")
    u = body["unit_cents"]
    if (body["theta2_cents"], body["v_floor_cents"], body["c_ref_cents"], body["node_cap_cents"]) != (u, u // 4, u * 5 // 2, u * 15 // 4):
        raise InputError("params: theta2, v_floor, c_ref and node_cap must be U, U/4, 2.5U and 3.75U")
    for kind, row in body["proofs"].items():
        allowed = {"forge", "rent", "curve", "half_life_days", "day_factor_ppm", "assess", "units_per_cent", "age_cents", "rank_cents", "fallback_cents"}
        if not isinstance(row, dict) or not {"forge", "rent", "curve", "half_life_days", "day_factor_ppm"} <= set(row) <= allowed:
            raise InputError(f"params proofs.{kind}: unexpected fields")

    def ints(obj, where):
        for k, v in obj.items():
            if isinstance(v, dict):
                ints(v, where + "." + k)
            elif isinstance(v, (bool, float)):
                raise InputError(f"params {where}.{k} must be an integer")
    ints(body, "body")


def read_snapshot_v2(raws) -> SnapshotV2:
    snap = SnapshotV2()
    for n, raw in raws:
        if raw.get("type") not in RECORD_TYPES_V2:
            raise InputError(f"line {n}: unknown record type {raw.get('type')!r}")
        unknown = set(raw) - set(FIELD_ZERO_V2)
        if unknown:
            raise InputError(f"line {n}: unknown field(s) {sorted(unknown)}")
        for k, v in raw.items():
            if k == "body":
                continue
            zero = FIELD_ZERO_V2[k]
            if isinstance(v, bool) or type(v) is not type(zero):
                raise InputError(f"line {n}: field {k} has the wrong type")
        rec = Rec2(raw)
        if rec.type == "meta":
            if rec.schema != SNAPSHOT_SCHEMA_V2:
                raise InputError(f"line {n}: snapshot schema {rec.schema} is not 2")
            snap.meta = rec
        elif rec.type == "params":
            check_params_v2(rec.body, rec.version)
            snap.params = rec.body
            snap.params_version = rec.version
        else:
            snap.lists[rec.type].append(rec)
    if snap.params is None:
        raise InputError("the snapshot has no params record")
    return snap


# --- RFC 0020 §1-§2: the judgement record and the score (internal/judge)

J_NEUTRAL, J_MIN, J_MAX = 50, 0, 100
RELATIONSHIP_PPM = {"owner": 0, "affiliate": 0, "paid": 0, "competitor": 500_000, "outside_source": 0, "lab": 0}


def j_clamp(x):
    return min(J_MAX, max(J_MIN, x))


def j_side(x):
    return J_MAX if x > J_NEUTRAL else (J_MIN if x < J_NEUTRAL else J_NEUTRAL)


def sat_add(a, b):
    return min(a + b, INT64_MAX_V2)


def j_median(points, prior):
    pts = [(j_clamp(x), w) for x, w in points if w > 0]
    if prior > 0 or not pts:
        pts.append((J_NEUTRAL, max(1, prior)))
    pts.sort(key=lambda p: p[0])
    merged = [list(pts[0])]
    for x, w in pts[1:]:
        if merged[-1][0] == x:
            merged[-1][1] = sat_add(merged[-1][1], w)
        else:
            merged.append([x, w])
    total = 0
    for _, w in merged:
        total = sat_add(total, w)
    cum = 0
    for i, (x, w) in enumerate(merged):
        cum = sat_add(cum, w)
        twice = sat_add(cum, cum)
        if twice > total or (twice == total and i == len(merged) - 1):
            return x
        if twice == total:
            return (x + merged[i + 1][0]) // 2
    return J_NEUTRAL


def j_consensus(points, prior_weight):
    w, n = 0, 0
    for _, pw in points:
        if pw > 0:
            w = sat_add(w, pw)
            n += 1
    prior = mul_div(w, max(0, prior_weight), n) if n > 0 else 0
    return j_median(points, prior)


def j_gain(x, c0, cT, coarse):
    x, c0, cT = j_clamp(x), j_clamp(c0), j_clamp(cT)
    if coarse:
        x = j_side(x)
        s = (x > c0) - (x < c0)
        return gdiv(s * (cT - c0) * PPM, J_MAX - J_MIN)
    return gdiv((abs(c0 - cT) - abs(x - cT)) * PPM, J_MAX - J_MIN)


def j_weight(evidence, v, rel, decay):
    w = mul_div(max(0, evidence), max(0, v), PPM)
    w = mul_div(w, max(0, rel), PPM)
    return mul_div(w, max(0, decay), PPM)


# --- prices


def log10_ppm(n: int) -> int:
    """floor(1e6 × log10(n)) by the reference's integer steps: log2 with 30
    fractional bits by repeated squaring in Q62, over log2(10) in Q30."""
    if n <= 1:
        return 0
    k = n.bit_length() - 1
    y = n << (62 - k)
    frac = 0
    for _ in range(30):
        y = (y * y) >> 62
        frac <<= 1
        if y >= 1 << 63:
            frac |= 1
            y >>= 1
    return mul_div((k << 30) | frac, PPM, LOG2_TEN)


def domain_contribution(price, age_days, registered, rank, cv):
    if registered <= 0 and rank <= 0:
        return min(price.get("fallback_cents", 0), price["forge"], price["rent"])
    c = 0
    if registered > 0:
        c += price["age_cents"] * cv.ramp(price["day_factor_ppm"], max(0, age_days)) // PPM
    if rank > 0:
        lg = log10_ppm(rank)
        if lg < 6 * PPM:
            c += mul_div(price["rank_cents"], 6 * PPM - lg, 6 * PPM)
    return min(c, min(price["forge"], price["rent"]))


def labels_of(u: UnionFind) -> dict:
    def rank(x):
        if x.startswith("domain:"):
            return 0
        return 2 if ":" in x else 1
    label = {}
    for x in sorted(u):
        rep = u.find(x)
        cur = label.get(rep)
        if cur is None or rank(x) < rank(cur) or (rank(x) == rank(cur) and x < cur):
            label[rep] = x
    return label


def flow_levels(U, node_cap):
    out = []
    for lv in (U // 8, U // 4, U // 2, U, 2 * U, node_cap):
        lv = min(lv, node_cap)
        if lv > 0 and (not out or lv > out[-1]):
            out.append(lv)
    return out


def pass_flow_levels(U, node_cap):
    """Version 10's levels: U/64, U/32, U/16, then flow_levels'."""
    out = []
    for lv in (U // 64, U // 32, U // 16):
        lv = min(lv, node_cap)
        if lv > 0 and (not out or lv > out[-1]):
            out.append(lv)
    for lv in flow_levels(U, node_cap):
        if not out or lv > out[-1]:
            out.append(lv)
    return out


def endorsement_key(r):
    return (r.seq, r.created_at, r.kind, r.voter, r.target, r.message_id, r.value)


class Graph:
    def __init__(self):
        self.labels, self.index, self.root_of = [], {}, {}
        self.world, self.cap = [], []
        self.src, self.dst, self.edge_cap = [], [], []
        self.levels = []
        self.recent = []
        self.pass_ = None  # version 10: each node's pass share


def set_pass(g: Graph, pass_share_ppm: int) -> None:
    """Each node's pass share (version 10): its surplus above its cap topped
    up to pass_share_ppm of what it keeps, never beyond its edges' capacity."""
    g.pass_ = None
    if pass_share_ppm <= 0:
        return
    out = [0] * len(g.labels)
    for k in range(len(g.src)):
        out[g.src[k]] = min(out[g.src[k]] + g.edge_cap[k], 1 << 60)
    g.pass_ = []
    for i in range(len(g.labels)):
        keep = min(g.world[i], g.cap[i])
        surplus = g.world[i] - keep
        g.pass_.append(min(max(0, mul_div(keep, pass_share_ppm, PPM) - surplus), max(0, out[i] - surplus)))


def graph_flow(g: Graph, max_work: int, work: int):
    n = len(g.labels)
    standing, own, passed, edge = [0] * n, [0] * n, [0] * n, [0] * len(g.src)
    if n == 0:
        return standing, own, passed, edge, work
    S, T = n, n + 1
    net = Network(n + 2, max_work, work)
    inn = [-1] * n
    for i in range(n):
        w = g.world[i]
        own[i] = min(w, g.cap[i])
        if g.pass_ is not None:
            own[i] -= g.pass_[i]
        if w - own[i] > 0:
            inn[i] = net.add(S, i, w - own[i])
    ids = [net.add(g.src[k], g.dst[k], g.edge_cap[k]) for k in range(len(g.src))]
    sink = [net.add(i, T, 0) for i in range(n)]
    have = [0] * n
    for L in g.levels:
        for i in range(n):
            want = max(0, min(L, g.cap[i]) - own[i])
            net.cap[sink[i]] += want - have[i]
            have[i] = want
        net.maxflow(S, T)
    for i in range(n):
        got = net.flow_on(sink[i])
        standing[i] = own[i] + got
        if inn[i] >= 0:
            passed[i] = net.flow_on(inn[i])
        if g.pass_ is not None and g.pass_[i] > 0:
            kept = min(passed[i], got, g.pass_[i])
            own[i] += kept
            passed[i] -= kept
    for k, e in enumerate(ids):
        edge[k] = net.flow_on(e)
    return standing, own, passed, edge, net.work


def compute_unified(snap: SnapshotV2) -> dict:
    p = snap.params
    as_of = snap.meta.as_of
    D = day_of(as_of)
    H = p["half_life_days"]
    ws = as_of - p["window_days"] * DAY
    U = p["unit_cents"] * MC
    node_cap = p["node_cap_cents"] * MC
    cv = Curves()
    max_work = p["max_work"]
    work = 0

    # The carry.
    carry_recs = snap.of("carry")
    carry = None
    if carry_recs:
        carry = {"as_of": 0, "accounts": {}}
        runs = 0
        for r in sort_v2(carry_recs):
            if r.kind == "run":
                runs += 1
                carry["as_of"] = r.as_of
            elif r.kind == "world":
                if not r.account or r.account in carry["accounts"] or min(r.amount, r.time, r.backed, r.direct, r.standing, r.fraction_ppm) < 0 \
                        or r.fraction_ppm > PPM:
                    raise InputError(f"carry world record for {r.account!r} is out of range or repeated")
                carry["accounts"][r.account] = r
            else:
                raise InputError(f"unknown carry kind {r.kind!r}")
        if runs != 1:
            raise InputError(f"the carry needs one run record, not {runs}")
        if carry["as_of"] > as_of:
            raise InputError("the carry is after the run")
    carry_in = hashlib.sha256(canonical([plain_v2(r) for r in sort_v2(carry_recs)]).encode()).hexdigest() if carry_recs else ""
    prev_as_of = max(carry["as_of"], as_of - 3650 * DAY) if carry else ws
    prev_d = day_of(prev_as_of)

    def carried(a):
        return carry["accounts"].get(a, Rec2()) if carry else Rec2()

    # The penalty log.
    log = {}
    for r in sort_v2(snap.of("penalty")):
        if not r.id or not r.account:
            raise InputError("a penalty record needs an id and an account")
        e = log.get(r.id)
        sig = (r.kind, r.created_at, r.ends_at, r.value, r.state == "pending", r.evidence)
        if e is None:
            e = log[r.id] = {"id": r.id, "trigger": r.kind, "evidence": r.evidence, "start": r.created_at, "end": r.ends_at, "level": r.value,
                             "pending": r.state == "pending", "lifted": False, "members": [], "burned": [], "liabilities": [], "sig": sig}
        elif e["sig"] != sig:
            raise InputError(f"penalty entry {r.id!r} has members that disagree")
        if r.kind not in TRIGGERS:
            raise InputError(f"penalty entry {r.id!r} has an unknown trigger {r.kind!r}")
        e["members"].append(r.account)
    for r in sort_v2(snap.of("burn")):
        if r.id in log and r.root:
            log[r.id]["burned"].append(r.root)
    for r in sort_v2(snap.of("liability")):
        if r.id in log and r.account:
            log[r.id]["liabilities"].append(r)
    for r in sort_v2(snap.of("lift")):
        if r.id in log and r.created_at <= as_of:
            log[r.id]["lifted"] = True
    log_ids = sorted(log)

    def active_at(e, t):
        return not e["lifted"] and not e["pending"] and e["start"] <= t < e["end"]

    # Accounts seen anywhere.
    known = set()
    first_seen = {}
    for x in snap.of("account"):
        if x.account:
            known.add(x.account)
        if x.first_seen > 0 and (first_seen.get(x.account, 0) == 0 or x.first_seen < first_seen[x.account]):
            first_seen[x.account] = x.first_seen
    for x in snap.of("post"):
        known.update(a for a in (x.account, x.reply_to_account) if a)
    for x in snap.of("endorsement"):
        known.update(a for a in (x.voter, x.target) if a)
    for x in snap.of("proof"):
        known.update(a for a in (x.account,) if a)
    for x in snap.of("payment"):
        known.update(a for a in (x.account, x.to) if a)
    for x in snap.of("edge") + snap.of("transfer"):
        known.update(a for a in (x.from_, x.to) if a)
    for x in snap.of("claim"):
        known.update(a for a in (x.account,) if a)
    for x in snap.of("review"):
        if x.account:
            known.add(x.account)
        if x.target.startswith("agent:") and len(x.target) > 6:
            known.add(x.target[6:])
    for x in snap.of("owner"):
        if x.account:
            known.add(x.account)
    if carry:
        known.update(carry["accounts"])
    for e in log.values():
        known.update(e["members"])
    known.discard("")

    # A breaker holds until its trust_until, or (version 11) its reason's
    # breaker_trust_days after it started if sooner (RFC 0021 §2.2).
    breaker_days = p.get("breaker_trust_days", {})

    def breaker_until(x):
        if x.kind in breaker_days:
            return min(x.trust_until, x.started_at + breaker_days[x.kind] * DAY)
        return x.trust_until

    reset = set()
    for x in snap.of("breaker"):
        if x.started_at <= as_of < breaker_until(x):
            reset.add(x.account)
    since = snap.meta.pause_new_keys_since
    if since > 0:
        for a, t in first_seen.items():
            if t > since:
                reset.add(a)

    burned = set()
    for e in log.values():
        if not e["lifted"]:
            burned.update(e["burned"])

    # Roots.
    suffixes = set(p["domain_suffixes"])
    fresh = as_of - p["proof_fresh_days"] * DAY
    proofs_p = p["proofs"]

    def counts(x):
        if x.created_at > as_of:
            return False
        if x.kind == "domain" or proofs_p.get(x.kind, {}).get("assess", ""):
            return x.state == "verified" and fresh <= x.checked_at <= as_of
        if x.kind == "ed25519":
            return x.state in ("proof_attached", "verified")
        return x.state == "verified"
    proofs = sort_v2(snap.of("proof"))
    base, full = UnionFind(), UnionFind()
    for x in proofs:
        if not counts(x):
            continue
        if x.kind == "domain":
            d = domain_root(x.link_value, suffixes)
            base.union(x.account, d)
            full.union(x.account, d)
        elif x.kind == "ed25519":
            if x.link_account:
                base.union(x.account, x.link_account)
                full.union(x.account, x.link_account)
        elif x.kind == "wallet":
            if x.root and x.root not in burned:
                full.union(x.account, x.root)
    payments = sort_v2(snap.of("payment"))
    for x in payments:
        if x.to and x.link_value and x.link_value not in burned and x.created_at < as_of:
            full.union(x.to, x.link_value)
    label = labels_of(full)
    base_label = labels_of(base)

    def root_of(a):
        return label[full.find(a)] if a in full else a

    def base_root(a):
        return base_label[base.find(a)] if a in base else a

    funded_from = as_of - H * DAY
    funded = set()
    money_out = {}

    def link(frm, to, at):
        if not frm or not to or frm == to or at < funded_from or at >= as_of:
            return
        funded.add((frm, to))
        funded.add((to, frm))
        money_out.setdefault(frm, []).append(to)
    for x in snap.of("transfer"):
        if x.amount > 0:
            link(x.from_, x.to, x.created_at)
    for x in payments:
        if x.amount > 0:
            link(x.account, x.to, x.created_at)
    for a in money_out:
        money_out[a].sort()

    def indep(a, b):
        return a != b and root_of(a) != root_of(b) and (a, b) not in funded

    member, liable = {}, {}

    def apply_log(e):
        for m in e["members"]:
            root = root_of(m)
            if root not in member or e["id"] < member[root]["id"]:
                member[root] = e
        for l in e["liabilities"]:
            if l.created_at <= as_of < l.ends_at:
                root = root_of(l.account)
                cur = liable.get(root)
                if cur is None or l.fraction_ppm > cur["fraction_ppm"]:
                    liable[root] = {"entry": e["id"], "role": "backer", "fraction_ppm": min(PPM, l.fraction_ppm), "level": l.value, "ends_at": l.ends_at}
    for i in log_ids:
        if active_at(log[i], as_of):
            apply_log(log[i])

    def penalised(a):
        return root_of(a) in member

    # Proofs.
    claims = []
    for x in proofs:
        price = proofs_p.get(x.kind, {})
        if x.kind != "domain" and not price.get("assess", ""):
            continue
        it = {"kind": "proof", "source": x.kind, "state": x.state, "root": "", "price_cents": 0, "cents": 0, "note": ""}
        if x.kind == "domain":
            it["root"] = domain_root(x.link_value, suffixes)
        elif x.root:
            it["root"] = x.root
        else:
            it["root"] = x.kind + ":" + x.link_value
        cents = value = 0
        if not counts(x):
            it["note"] = "not counted: not verified within proof_fresh_days"
        elif it["root"] in burned:
            it["state"], it["note"] = "burned", "burned by a penalty: prices 0 on any key"
        elif x.kind == "domain":
            cents = domain_contribution(price, D - day_of(x.registered_at), x.registered_at, x.rank, cv)
            if x.registered_at <= 0 and x.rank <= 0:
                it["note"] = "registration age and rank not yet fetched: priced at the domain row's fallback"
            else:
                value = cents  # priced by its signals: no floor to drop
        else:
            cents, value = assessed_contribution(price, x.assessed), assessed_value(price, x.assessed)
        it["price_cents"] = cents
        claims.append((x.account, it, cents, value))
    # From version 12, a capped row's fallback floor counts once per (kind,
    # node root): the best claim keeps it, the others price at their
    # assessed value (C492). From version 13 a domain priced at its row's
    # fallback (value 0) takes the same rule (C515); one priced by its
    # signals still stacks. Versions up to 11 keep each claim's floor, up
    # to 12 each domain's.
    floor_of = {}
    for i, (a, it, price, value) in enumerate(claims):
        row = proofs_p.get(it["source"], {})
        capped = snap.params_version >= FLOOR_ONCE_VERSION and row.get("assess", "") == "capped" and row.get("fallback_cents", 0) > 0
        domain = snap.params_version >= DOMAIN_FLOOR_ONCE_VERSION and it["source"] == "domain" and value < price
        if price <= 0 or not (capped or domain):
            continue
        k = (it["source"], root_of(a))
        j = floor_of.get(k)
        # The highest price keeps the floor; at equal price the higher value,
        # then the lower account.
        if j is None or (price, value) > (claims[j][2], claims[j][3]) or ((price, value) == (claims[j][2], claims[j][3]) and a < claims[j][0]):
            floor_of[k] = i
    for i, (a, it, price, value) in enumerate(claims):
        j = floor_of.get((it["source"], root_of(a)))
        if j is None or j == i or value >= price:
            continue
        it = dict(it, price_cents=value, note="fallback counted once per root: on " + claims[j][0])
        claims[i] = (a, it, value, value)
    claims = [(a, it, price) for a, it, price, _ in claims]
    best_of, claimants = {}, {}
    for i, (a, it, price) in enumerate(claims):
        if price <= 0:
            continue
        k = (it["root"], root_of(a))
        j = best_of.get(k)
        if j is None or price > claims[j][2] or (price == claims[j][2] and a < claims[j][0]):
            best_of[k] = i
        claimants.setdefault(it["root"], set()).add(root_of(a))
    proof_mc, items, proof_roots_of = {}, {}, {}
    for i, (a, it, price) in enumerate(claims):
        it = dict(it)
        if price > 0:
            proof_roots_of.setdefault(a, []).append(it["root"])
            k = (it["root"], root_of(a))
            if best_of[k] == i:
                n = len(claimants[it["root"]])
                share = price * MC // n
                proof_mc[a] = proof_mc.get(a, 0) + share
                it["cents"] = share // MC
                if n > 1:
                    it["note"] = f"shared with {n - 1} other root(s): split"
            else:
                b = claims[best_of[k]]
                it["note"] = "saturated by " + b[1]["source"] + " on " + b[0]
        items.setdefault(a, []).append(it)

    # Prior direct costs and standing: the carry's, and at least this run's
    # own costs (proofs held now, faded as the carry left them, and money
    # paid in since the carry; a first run counts all of it) (C320c).
    money_all = {}
    for x in payments:
        if not x.to and x.amount > 0 and x.created_at < as_of and (not carry or x.created_at >= prev_as_of):
            money_all[x.account] = money_all.get(x.account, 0) + min(x.amount, 1 << 40) * MC

    def own_direct(a):
        if carry and a in carry["accounts"]:
            return mul_div(proof_mc.get(a, 0), carry["accounts"][a].fraction_ppm, PPM) + money_all.get(a, 0)
        return proof_mc.get(a, 0) + money_all.get(a, 0)

    def prior_direct(a):
        if carry:
            return max(carried(a).direct * MC, own_direct(a))
        return own_direct(a)

    span = max(0, D - prev_d)
    backed = {}
    if carry:
        for a, c in carry["accounts"].items():
            if c.backed > 0:
                backed[a] = mul_div(c.backed, cv.decay(p["day_factor_ppm"], span), PPM)
    used = {}

    def budget(b):
        return max(0, prior_direct(b) - backed.get(b, 0) - used.get(b, 0))
    # Settled USDC is backed by at least the wallet row's fallback (C320c).
    settled_floor = proofs_p.get("wallet", {}).get("fallback_cents", 0) * MC

    def settled_budget(b):
        return max(0, max(prior_direct(b), settled_floor) - backed.get(b, 0) - used.get(b, 0))

    reaches = {}

    def reach(frm):
        if frm in reaches:
            return reaches[frm]
        m = {frm}
        queue = [frm]
        while queue:
            x = queue.pop(0)
            for y in money_out.get(x, []):
                if y not in m:
                    m.add(y)
                    queue.append(y)
        reaches[frm] = m
        return m
    paid, paid_n, paid_out, paid_out_n = {}, {}, {}, {}
    for x in payments:
        if not x.to or x.amount <= 0 or x.created_at < funded_from or x.created_at >= as_of:
            continue
        a, b = x.account, x.to
        if a == b or root_of(a) == root_of(b) or penalised(a) or penalised(b) or a in reach(b):
            continue
        settled = x.kind in SETTLED_PAYMENT_KINDS
        room = settled_budget(b) if settled else budget(b)
        credit = min(min(x.amount, 1 << 40) * MC, room)
        if credit <= 0:
            continue
        used[b] = used.get(b, 0) + credit
        if settled:
            paid_out[a] = paid_out.get(a, 0) + credit
            paid_out_n[a] = paid_out_n.get(a, 0) + 1
        else:
            paid[a] = paid.get(a, 0) + credit
            paid_n[a] = paid_n.get(a, 0) + 1

    def prior_standing(a):
        own = min(own_direct(a) + paid_out.get(a, 0), node_cap) // MC
        if carry:
            return max(carried(a).standing, own)
        return own

    # Activity.
    responses = {}

    def respond(by, to, at):
        if not by or not to or at < prev_as_of or at >= as_of or by in reset or penalised(by) or not indep(by, to) \
                or prior_standing(by) < p["v_floor_cents"]:
            return
        responses.setdefault(to, []).append((day_of(at), by))
    for x in snap.of("post"):
        if x.reply_to_account:
            respond(x.account, x.reply_to_account, x.created_at)
    for x in snap.of("endorsement"):
        if (x.kind == "vote" and x.value != 0) or (x.kind == "vouch" and x.value == 1):
            respond(x.voter, x.target, x.created_at)
    for x in snap.of("edge"):
        respond(x.from_, x.to, x.created_at)
    review_owners = {}
    for x in sort_v2(snap.of("owner")):
        review_owners.setdefault(x.target, []).append(x.account)
    for x in snap.of("review"):
        owners = list(review_owners.get(x.target, []))
        if x.target.startswith("agent:"):
            owners.append(x.target[6:])
        for o in owners:
            respond(x.account, o, x.created_at)
    active_on, responders_of = {}, {}
    for a, lst in responses.items():
        days = {}
        for d, by in lst:
            days.setdefault(d, set()).add(by)
        for d, s in days.items():
            active_on.setdefault(d, []).append(a)
            responders_of[(a, d)] = sorted(s)
    for d in active_on:
        active_on[d].sort()

    money_in = {}
    for x in payments:
        if x.to or x.amount <= 0 or x.created_at >= as_of or (carry and x.created_at < prev_as_of):
            continue
        d = max(prev_d, day_of(x.created_at))
        mi = money_in.setdefault(x.account, {})
        mi[d] = mi.get(d, 0) + min(x.amount, 1 << 40) * MC
    first_cost = {}

    def cost(a, at):
        d = day_of(at)
        if at < as_of and (first_cost.get(a, 0) == 0 or d < first_cost[a]):
            first_cost[a] = d
    for x in payments:
        if not x.to and x.amount > 0:
            cost(x.account, x.created_at)
    for x in proofs:
        if proofs_p.get(x.kind, {}).get("assess", "") and counts(x):
            cost(x.account, x.created_at)
    accounts = sorted(known)
    world = {}
    for a in accounts:
        w = {"money": 0, "time": 0, "fade": PPM, "last": max(prev_d, first_cost.get(a, 0)), "active": 0}
        if first_seen.get(a, 0) > 0:
            w["last"] = max(w["last"], day_of(first_seen[a]))
        if carry and a in carry["accounts"]:
            c = carry["accounts"][a]
            w["money"], w["time"], w["fade"], w["last"] = c.amount, c.time, c.fraction_ppm, c.last_active
        world[a] = w
    f = p["dormant_day_factor_ppm"]
    day_price, time_cap = p["day_price_cents"] * MC, p["time_cap_cents"] * MC
    new_backed = {}
    for d in range(prev_d, D):
        for a in accounts:
            w = world[a]
            if d - w["last"] > p["grace_days"]:
                w["money"], w["time"], w["fade"] = mul_div(w["money"], f, PPM), mul_div(w["time"], f, PPM), mul_div(w["fade"], f, PPM)
            w["money"] += money_in.get(a, {}).get(d, 0)
        for a in active_on.get(d, []):
            w = world[a]
            w["last"], w["active"] = d, w["active"] + 1
            if w["time"] + day_price > time_cap or day_price <= 0:
                continue
            for by in responders_of[(a, d)]:
                if budget(by) + paid_out.get(by, 0) - new_backed.get(by, 0) >= day_price:
                    new_backed[by] = new_backed.get(by, 0) + day_price
                    w["time"] += day_price
                    break

    world_mc, direct_mc = {}, {}
    for a in accounts:
        w = world[a]
        if penalised(a):
            w["money"], w["time"] = 0, 0
            continue
        pr = mul_div(proof_mc.get(a, 0), w["fade"], PPM)
        direct_mc[a] = pr + w["money"]
        world_mc[a] = pr + w["money"] + w["time"] + paid.get(a, 0) + paid_out.get(a, 0)

    # Judgements.
    owners = {}

    def own(subject, account):
        if account:
            owners.setdefault(subject, set()).add(account)
    for x in sort_v2(snap.of("owner")):
        own(x.target, x.account)
    act_ev = p["act_evidence"]
    entries = []

    def add(j, withdraw, owner):
        if not j["author"] or not j["subject"] or j["author"] in reset or j["at"] < ws or j["at"] >= as_of:
            return
        own(j["subject"], owner)
        j["root"] = root_of(j["author"])
        entries.append({"j": j, "withdraw": withdraw, "close": -1})

    def judgement(id_, act, author, subject, x, coarse, evidence, at, relationship=""):
        return {"id": id_, "act": act, "author": author, "subject": subject, "x": x, "coarse": coarse, "evidence": evidence,
                "relationship": relationship, "at": at}
    for r in sorted(snap.of("endorsement"), key=lambda r: (endorsement_key(r), record_key_v2(r))):
        if not r.target:
            continue
        id_ = "e" + str(r.seq)
        if r.kind == "vote":
            if not r.message_id:
                continue
            ok = r.value in (1, -1)
            x = J_MAX if r.value == 1 else J_MIN
            add(judgement(id_, "vote", r.voter, "post:" + r.message_id, x if ok else 0, True, act_ev["vote"], r.created_at), not ok, r.target)
        elif r.kind == "vouch":
            ok = r.value == 1
            add(judgement(id_, "vouch", r.voter, "agent:" + r.target, 80 if ok else 0, ok, act_ev["vouch"], r.created_at), not ok, r.target)
    for r in sort_v2(snap.of("edge")):
        if r.kind == "work_accept":
            add(judgement("work:" + r.id, "work_accept", r.from_, "agent:" + r.to, 75, True, act_ev["work_accept"], r.created_at), False, r.to)
        elif r.kind == "witness" and r.id and r.value != 0:
            add(judgement("witness:" + r.from_ + ":" + r.id, "witness", r.from_, "claim:" + r.to + ":" + r.id, J_MAX if r.value > 0 else J_MIN, True,
                          act_ev["witness"], r.created_at), False, r.to)
    for r in sort_v2(snap.of("review")):
        add(judgement("review:" + r.id, "review", r.account, r.target, min(J_MAX, max(J_MIN, r.value)), False, r.kind, r.created_at, r.link_value), False, "")
    for e in entries:
        s = e["j"]["subject"]
        if s.startswith("agent:"):
            own(s, s[6:])
    by_subject = {}
    for e in entries:
        j = e["j"]
        root = root_of(j["author"])
        if any(o == j["author"] or root_of(o) == root for o in owners.get(j["subject"], ())):
            continue
        by_subject.setdefault(j["subject"], []).append(e)
    for s, lst in by_subject.items():
        lst.sort(key=lambda e: (e["j"]["at"], e["j"]["id"], e["j"]["author"]))
        last = {}
        for i, e in enumerate(lst):
            if e["j"]["root"] in last:
                lst[last[e["j"]["root"]]]["close"] = i
            last[e["j"]["root"]] = i
    subjects = sorted(by_subject)
    ev_w = p["evidence_weight_ppm"]

    def evidence_ppm(j):
        return ev_w.get(j["evidence"], 0)

    def decay_h(days):
        return cv.decay(p["day_factor_ppm"], days)

    # Graph.
    def new_graph():
        g = Graph()
        wsum = {}
        for a in accounts:
            root = root_of(a)
            g.root_of[a] = root
            wsum[root] = wsum.get(root, 0) + world_mc.get(a, 0)
        g.labels = sorted(wsum)
        for i, root in enumerate(g.labels):
            g.index[root] = i
            w, c = wsum[root], node_cap
            if root in member:
                w, c = 0, 0
            elif root in liable:
                fr = liable[root]["fraction_ppm"]
                w, c = mul_div(w, PPM - fr, PPM), mul_div(c, PPM - fr, PPM)
            g.world.append(w)
            g.cap.append(c)
        g.levels = pass_flow_levels(U, node_cap) if p.get("pass_share_ppm", 0) > 0 else flow_levels(U, node_cap)
        return g

    def set_edges(g, acc):
        sums = {}
        g.recent = []
        frm = as_of - p["penalty"]["backer_edge_days"] * DAY
        for s in subjects:
            dsts, seen = [], set()
            for o in sorted(owners.get(s, ())):
                root = root_of(o)
                if root in g.index and g.index[root] not in seen and root not in member:
                    seen.add(g.index[root])
                    dsts.append(g.index[root])
            dsts.sort()
            for e in by_subject[s]:
                if e["withdraw"] or e["close"] >= 0:
                    continue
                j = e["j"]
                x = j["x"]
                if j["coarse"]:
                    if x <= 50:
                        continue
                    x = p["coarse_x"]
                if x <= 50:
                    continue
                src_root = root_of(j["author"])
                if src_root not in g.index or src_root in member:
                    continue
                src = g.index[src_root]
                to = [d for d in dsts if d != src]
                if not to:
                    continue
                c = mul_div(U, (x - 50) * PPM // 50, PPM)
                c = mul_div(c, evidence_ppm(j), PPM)
                c = mul_div(c, RELATIONSHIP_PPM.get(j["relationship"], PPM), PPM)
                c = mul_div(c, decay_h(D - day_of(j["at"])), PPM)
                c = mul_div(c, acc(j["author"]), PPM)
                share = c // len(to)
                if share <= 0:
                    continue
                for d in to:
                    sums[(src, d)] = sums.get((src, d), 0) + share
                    if j["at"] >= frm:
                        g.recent.append((j["author"], d, share, j["at"]))
        g.src, g.dst, g.edge_cap = [], [], []
        for (s_, d_) in sorted(sums):
            c = sums[(s_, d_)]
            if g.labels[s_] in liable:
                c = mul_div(c, PPM - liable[g.labels[s_]]["fraction_ppm"], PPM)
            if c <= 0:
                continue
            g.src.append(s_)
            g.dst.append(d_)
            g.edge_cap.append(c)
        set_pass(g, p.get("pass_share_ppm", 0))

    g = new_graph()
    set_edges(g, lambda a: PPM)
    st1, _, _, _, work = graph_flow(g, max_work, work)

    def s1(a):
        i = g.index.get(root_of(a))
        return st1[i] // MC if i is not None else 0

    # Accuracy.
    m = p["min_judges"]
    v1 = {}

    def v_of(a):
        if a not in v1:
            v1[a] = vote_weight_ppm(s1(a), p["v0_ppm"], p["c_ref_cents"], p["v_floor_cents"])
        return v1[a]

    def weight_at(j, t):
        return j_weight(evidence_ppm(j), v_of(j["author"]), RELATIONSHIP_PPM.get(j["relationship"], PPM), decay_h(day_of(t) - day_of(j["at"])))

    def median_x(j):
        return j_side(j["x"]) if j["coarse"] else j["x"]

    def latest(lst, frm, to, t, keep):
        newest, roots = {}, []
        for i in range(frm, to):
            if not keep(lst[i]):
                continue
            r = lst[i]["j"]["root"]
            if r not in newest:
                roots.append(r)
            newest[r] = i
        pts, k = [], 0
        for r in sorted(roots):
            e = lst[newest[r]]
            if e["withdraw"]:
                continue
            w = weight_at(e["j"], t)
            pts.append((median_x(e["j"]), w))
            if w > 0:
                k += 1
        return pts, k
    gain, marked = {}, {}
    judged = opened_n = 0
    truncated = False
    acc_work = 0
    for s in subjects:
        lst = by_subject[s]
        pen = any(penalised(o) for o in owners.get(s, ()))
        for i, e in enumerate(lst):
            if e["withdraw"]:
                continue
            judged += 1
            if truncated:
                continue
            acc_work += len(lst)
            if acc_work > max_work:
                truncated = True
                continue
            T, end = as_of, len(lst)
            if e["close"] >= 0:
                T, end = lst[e["close"]]["j"]["at"], e["close"]
            j = e["j"]
            before, _ = latest(lst, 0, i, j["at"], lambda o, j=j: o["j"]["root"] != j["root"])
            c0 = j_consensus(before, m)
            after, k = latest(lst, i + 1, end, T, lambda o, j=j: indep(j["author"], o["j"]["author"]))
            cT = j_median(after, 0)
            if pen:
                cT = J_MIN
            elif k < m:
                continue
            gain[j["author"]] = gain.get(j["author"], 0) + j_gain(j["x"], c0, cT, j["coarse"])
            marked[j["author"]] = marked.get(j["author"], 0) + 1
    work += acc_work

    def accuracy(a):
        n = marked.get(a, 0)
        if n + m <= 0:
            return PPM
        return min(2 * PPM, max(PPM // 2, PPM + gdiv(2 * gain.get(a, 0), n + m)))
    set_edges(g, accuracy)

    # Detectors.
    det = p["detectors"]
    evidence = []
    accounts_of = {}
    for a in accounts:
        accounts_of.setdefault(root_of(a), []).append(a)
    frm = as_of - det["funnel_days"] * DAY
    claimed, spent = {}, {}
    for x in snap.of("claim"):
        if D - det["funnel_days"] <= x.day < D:
            claimed[x.account] = claimed.get(x.account, 0) + x.claimed
            spent[x.account] = spent.get(x.account, 0) + x.spent
    senders = {}
    for x in snap.of("transfer"):
        if x.created_at < frm or x.created_at >= as_of or x.from_ == x.to or not x.from_ or not x.to or x.amount <= 0:
            continue
        senders.setdefault(x.to, set()).add(x.from_)
    in_funnel = {}
    for to in sorted(senders):
        farm = [s for s in senders[to] if claimed.get(s, 0) > 0 and spent.get(s, 0) * PPM <= det["funnel_spend_ppm"] * claimed[s]]
        if len(farm) < det["funnel_k"]:
            continue
        members = sorted(farm + [to])
        ev = {"id": evidence_id("funnel", D, members), "kind": "funnel", "members": members, "detector_version": det["version"],
              "detail": canonical({"recipient": to, "senders": len(farm), "window_days": det["funnel_days"]})}
        for mm in members:
            in_funnel.setdefault(mm, ev["id"])
        evidence.append(ev)
    if in_funnel:
        edges = [(g.src[k], g.dst[k], g.edge_cap[k]) for k in range(len(g.src))]
        for scc in strongly_connected(len(g.labels), edges):
            if len(scc) < det["ring_min"]:
                continue
            inside = set(scc)
            inn, total = {}, {}
            for s_, d_, w in edges:
                if d_ in inside:
                    total[d_] = total.get(d_, 0) + w
                    if s_ in inside:
                        inn[d_] = inn.get(d_, 0) + w
            ok = True
            members = []
            for v in scc:
                if total.get(v, 0) == 0 or inn.get(v, 0) * PPM < det["ring_inside_ppm"] * total[v]:
                    ok = False
                members += accounts_of.get(g.labels[v], [])
            members.sort()
            funnel = ""
            for mm in members:
                fid = in_funnel.get(mm, "")
                if fid and (funnel == "" or fid < funnel):
                    funnel = fid
            if not ok or not funnel:
                continue
            evidence.append({"id": evidence_id("ring", D, members), "kind": "ring", "members": members, "detector_version": det["version"],
                             "detail": canonical({"roots": len(scc), "funnel": funnel})})
    by_address = {}
    for x in snap.of("proof"):
        if x.kind == "wallet" and x.state == "verified" and fresh <= x.checked_at <= as_of and x.created_at <= as_of and x.root:
            by_address.setdefault(x.root, set()).add(base_root(x.account))
    for x in payments:
        if x.to and x.link_value and x.created_at < as_of:
            by_address.setdefault(x.link_value, set()).add(base_root(x.to))
    addresses = sorted(a for a, roots in by_address.items() if len(roots) >= 2)
    if addresses:
        since_h = as_of - H * DAY
        touched = set()

        def touch(a, b):
            ra, rb = base_root(a), base_root(b)
            if ra != rb:
                touched.add((ra, rb))
                touched.add((rb, ra))
        for s in subjects:
            for e in by_subject[s]:
                if e["j"]["at"] < since_h:
                    continue
                for o in owners.get(s, ()):
                    touch(e["j"]["author"], o)
        for a, b in funded:
            touch(a, b)
        for addr in addresses:
            roots = sorted(by_address[addr])
            hit = set()
            for i, a in enumerate(roots):
                for b in roots[i + 1:]:
                    if (a, b) in touched:
                        hit.add(a)
                        hit.add(b)
            if len(hit) < 2:
                continue
            members = [a for a in accounts if base_root(a) in hit]
            if not members:
                continue
            evidence.append({"id": evidence_id("shared_wallet", D, members), "kind": "shared_wallet", "members": members,
                             "detector_version": det["version"], "detail": canonical({"address": addr, "roots": len(hit)})})
    evidence.sort(key=lambda e: e["id"])

    # Penalties.
    pp = p["penalty"]

    def escalation(roots, is_backer):
        k = 0
        since_e = as_of - pp["escalation_days"] * DAY
        for i in log_ids:
            e = log[i]
            if e["lifted"] or e["pending"] or e["start"] <= since_e or e["start"] > as_of:
                continue
            if is_backer:
                if any(root_of(l.account) in roots for l in e["liabilities"]):
                    k += 1
                continue
            if any(root_of(mm) in roots for mm in e["members"]):
                k += 1
        return min(pp["max_level"], k + 1)

    def duration(k):
        d = pp["base_days"]
        i = 1
        while i < k and d < 3650:
            d *= pp["duration_factor"]
            i += 1
        return min(d, 3650) * DAY

    def recent_cap_into(roots, frm_):
        out = {}
        for author, dst, cap, at in g.recent:
            if at >= frm_ and g.labels[dst] in roots and g.root_of[author] not in roots:
                out[author] = out.get(author, 0) + cap
        return out

    def open_entry(id_, trigger, ev_ref, members, level, start, end, is_new):
        roots = {root_of(mm) for mm in members}
        if level <= 0:
            level = escalation(roots, False)
        if end <= 0:
            end = start + duration(level)
        out = {"id": id_, "trigger": trigger, "opened": is_new, "members": members, "level": level, "starts_at": start, "ends_at": end,
               "evidence": ev_ref, "burned": [], "backers": [], "burned_cents": 0}
        burn_set = set()
        for a in accounts:
            if root_of(a) in roots:
                out["burned_cents"] += world_mc.get(a, 0) // MC
                burn_set.update(proof_roots_of.get(a, []))
        out["burned"] = sorted(burn_set)
        c = recent_cap_into(roots, as_of - pp["backer_edge_days"] * DAY)
        for a in sorted(c):
            f_ppm = mul_div(c[a], PPM, c[a] + U)
            k = escalation({root_of(a)}, True)
            frac = f_ppm
            i = 1
            while i < k and frac < PPM:
                frac *= pp["backer_factor"]
                i += 1
            frac = min(PPM, frac)
            if frac <= 0:
                continue
            out["backers"].append({"account": a, "cap_cents": c[a] // MC, "level": k, "fraction_ppm": frac, "lost_cents": 0})
        return out
    penalties = []
    applying = set()
    for i in log_ids:
        e = log[i]
        if not e["pending"] or e["lifted"] or e["start"] > as_of:
            continue
        penalties.append(open_entry(e["id"], e["trigger"], e["evidence"], e["members"], e["level"], e["start"], e["end"], False))
        applying.update(root_of(mm) for mm in e["members"])
    opened = set()
    for ev in evidence:
        members = [mm for mm in ev["members"] if not penalised(mm) and root_of(mm) not in applying]
        if not members or ev["id"] in opened or ev["id"] in log:
            continue
        opened.add(ev["id"])
        penalties.append(open_entry(ev["id"], ev["kind"], ev["detail"], members, 0, as_of, 0, True))
    penalties.sort(key=lambda x: x["id"])
    pre = None
    if penalties:
        pre, _, _, _, work = graph_flow(g, max_work, work)
        for pen in penalties:
            if pen["starts_at"] > as_of or as_of >= pen["ends_at"]:
                continue
            e = {"id": pen["id"], "members": pen["members"], "liabilities": [
                Rec2({"account": b["account"], "fraction_ppm": b["fraction_ppm"], "created_at": pen["starts_at"], "ends_at": pen["ends_at"], "value": b["level"]})
                for b in pen["backers"]], "level": 0, "end": 0}
            apply_log(e)
        for a in accounts:
            if penalised(a):
                world[a]["money"], world[a]["time"] = 0, 0
                world_mc[a], direct_mc[a] = 0, 0
        g = new_graph()
        set_edges(g, accuracy)
    standing, own_f, passed, edge_flow, work = graph_flow(g, max_work, work)
    for pen in penalties:
        for b in pen["backers"]:
            k = g.index.get(root_of(b["account"]))
            if k is not None:
                b["lost_cents"] = max(0, pre[k] - standing[k]) // MC

    # Scores.
    def band_name(c):
        if c >= p["node_cap_cents"]:
            return "trusted"
        return "proven" if c >= p["theta2_cents"] else "signed"
    summary = {"world_cents": 0, "standing_cents": 0, "own_cents": 0, "passed_cents": 0, "top5_passed_ppm": 0, "sources": 0,
               "bands": {"signed": 0, "proven": 0, "trusted": 0}, "above_vote_floor": 0, "judgements": judged, "marked": sum(marked.values()),
               "truncated": truncated, "active_accounts": 0, "penalised": 0, "liable": 0, "penalties_open": 0}
    summary["penalties_open"] = sum(1 for i in log_ids if active_at(log[i], as_of)) + sum(1 for pen in penalties if pen["starts_at"] <= as_of < pen["ends_at"])
    passed_list = []
    for i in range(len(g.labels)):
        summary["world_cents"] += g.world[i] // MC
        summary["standing_cents"] += standing[i] // MC
        summary["own_cents"] += own_f[i] // MC
        summary["passed_cents"] += passed[i] // MC
        if passed[i] > 0:
            summary["sources"] += 1
            passed_list.append(passed[i])
    passed_list.sort(reverse=True)
    if passed_list:
        summary["top5_passed_ppm"] = mul_div(sum(passed_list[:5]), PPM, sum(passed_list))
    in_flows = [[] for _ in g.labels]
    out_flows = [[] for _ in g.labels]
    for k in range(len(g.src)):
        in_flows[g.dst[k]].append((g.src[k], g.edge_cap[k], edge_flow[k]))
        out_flows[g.src[k]].append((g.dst[k], g.edge_cap[k], edge_flow[k]))

    def top_flows(lst):
        s = sorted(lst, key=lambda x: (-x[2], -x[1], g.labels[x[0]]))
        return [{"root": g.labels[o], "cap_cents": c // MC, "cents": fl // MC} for o, c, fl in s[:20]], len(lst)

    def burn_preview(i):
        b = {"own_cents": g.world[i] // MC, "proof_roots": [], "backers": []}
        roots = set()
        for a in accounts:
            if g.root_of[a] == g.labels[i]:
                roots.update(proof_roots_of.get(a, []))
        b["proof_roots"] = sorted(roots)
        c = {}
        frm_ = as_of - pp["backer_edge_days"] * DAY
        for author, dst, cap, at in g.recent:
            if dst == i and at >= frm_:
                j = g.index.get(g.root_of[author])
                if j is not None and j != i:
                    c[j] = c.get(j, 0) + cap
        for j, cap in c.items():
            fr = mul_div(cap, PPM, cap + U)
            b["backers"].append({"root": g.labels[j], "fraction_ppm": fr, "cents": mul_div(standing[j], fr, PPM) // MC})
        b["backers"].sort(key=lambda x: (-x["cents"], x["root"]))
        b["backers"] = b["backers"][:20]
        return b
    scores, carry_out = [], []
    for a in accounts:
        root = root_of(a)
        i = g.index.get(root)
        w = world[a]
        sc = {"account": a, "root": root, "cents": 0}
        parts = {"world": [], "world_cents": 0, "direct_cents": 0, "root_world_cents": 0, "own_cents": 0, "received_cents": 0, "passed_cents": 0,
                 "node_cap_cents": p["node_cap_cents"], "backers": [], "backers_total": 0, "backs": [], "backs_total": 0,
                 "accuracy_ppm": accuracy(a), "judged": marked.get(a, 0), "grace_from_day": w["last"], "active_days": w["active"],
                 "grace_days": max(0, p["grace_days"] - (D - 1 - w["last"])), "fade_ppm": w["fade"], "penalty": None,
                 "burn": {"own_cents": 0, "proof_roots": [], "backers": []}}
        for it in items.get(a, []):
            it = dict(it)
            if it["cents"] > 0:
                it["cents"] = mul_div(it["cents"] * MC, w["fade"], PPM) // MC
            parts["world"].append(it)
        if w["money"] > 0:
            parts["world"].append({"kind": "money", "source": "paid_to_swarmmemo", "root": "money:" + a, "state": "counted",
                                   "price_cents": w["money"] // MC, "cents": w["money"] // MC, "note": ""})
        if w["time"] > 0:
            parts["world"].append({"kind": "time_present", "source": "active_days", "root": "time:" + a, "state": "counted",
                                   "price_cents": w["time"] // MC, "cents": w["time"] // MC,
                                   "note": f"{p['day_price_cents']}¢ per active day, at most {p['time_cap_cents']}¢"})
        if paid_out.get(a, 0) > 0:
            parts["world"].append({"kind": "money", "source": "usdc_paid", "root": "usdc:" + a, "state": "counted",
                                   "price_cents": paid_out[a] // MC, "cents": paid_out[a] // MC,
                                   "note": f"{paid_out_n[a]} settled USDC payment(s) to independent accounts within funded_days, each up to the payee's direct costs or the wallet row's fallback"})
        if paid.get(a, 0) > 0:
            parts["world"].append({"kind": "payments", "source": "independent_payments", "root": "payments:" + a, "state": "counted",
                                   "price_cents": paid[a] // MC, "cents": paid[a] // MC,
                                   "note": f"{paid_n[a]} payment(s) within funded_days, each up to the payee's direct costs"})
        parts["world_cents"], parts["direct_cents"] = world_mc.get(a, 0) // MC, direct_mc.get(a, 0) // MC
        if root in member:
            e = member[root]
            parts["penalty"] = {"entry": e["id"], "role": "member", "fraction_ppm": PPM, "level": e["level"], "ends_at": e["end"]}
            for pen in penalties:
                if pen["id"] == e["id"]:
                    parts["penalty"]["level"], parts["penalty"]["ends_at"] = pen["level"], pen["ends_at"]
            summary["penalised"] += 1
        elif root in liable:
            parts["penalty"] = dict(liable[root])
            summary["liable"] += 1
        if i is not None:
            sc["cents"] = standing[i] // MC
            parts["root_world_cents"], parts["own_cents"], parts["passed_cents"] = g.world[i] // MC, own_f[i] // MC, passed[i] // MC
            parts["received_cents"] = (standing[i] - own_f[i]) // MC
            parts["backers"], parts["backers_total"] = top_flows(in_flows[i])
            parts["backs"], parts["backs_total"] = top_flows(out_flows[i])
            parts["burn"] = burn_preview(i)
        sc["band"] = band_name(sc["cents"])
        sc["vote_weight_ppm"] = vote_weight_ppm(sc["cents"], p["v0_ppm"], p["c_ref_cents"], p["v_floor_cents"])
        sc["parts"] = parts
        if w["active"] > 0:
            summary["active_accounts"] += 1
        summary["bands"][sc["band"]] += 1
        if sc["cents"] >= p["v_floor_cents"]:
            summary["above_vote_floor"] += 1
        scores.append(sc)
        ca = {"account": a, "money": w["money"], "time": w["time"], "fade_ppm": w["fade"], "last_active": w["last"],
              "direct": direct_mc.get(a, 0) // MC, "standing": sc["cents"], "backed": backed.get(a, 0) + new_backed.get(a, 0)}
        if penalised(a):
            ca["money"], ca["time"] = 0, 0
        carry_out.append(ca)
    inputs = {"events_seq": snap.meta.events_seq, "endorsements_seq": snap.meta.endorsements_seq, "ledger_seq": snap.meta.ledger_seq,
              "accounts": len(snap.of("account")), "posts": len(snap.of("post")), "endorsements": len(snap.of("endorsement")),
              "proofs": len(snap.of("proof")), "transfers": len(snap.of("transfer")), "payments": len(snap.of("payment")),
              "acts": len(snap.of("edge")), "reviews": len(snap.of("review")), "penalty_entries": len(log_ids)}
    return {"schema": SNAPSHOT_SCHEMA_V2, "rule": "RFC 0021", "as_of": as_of, "params_version": snap.params_version,
            "params_sha256": hashlib.sha256(canonical(p).encode()).hexdigest(), "carry_in_sha256": carry_in, "inputs": inputs,
            "nodes": len(g.labels), "edges": len(g.src), "summary": summary, "scores": scores, "evidence": evidence, "penalties": penalties,
            "carry": {"as_of": as_of, "accounts": carry_out}}


# ---------------------------------------------------------------------------
# Ed25519 verification (RFC 8032 §5.1.7), cofactorless like Go's


_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _add(a, b):
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    A = (y1 - x1) * (y2 - x2) % _P
    B = (y1 + x1) * (y2 + x2) % _P
    C = 2 * t1 * t2 * _D % _P
    Dd = 2 * z1 * z2 % _P
    E, F, G, H = B - A, Dd - C, Dd + C, B + A
    return (E * F % _P, G * H % _P, F * G % _P, E * H % _P)


def _mul(s, point):
    q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            q = _add(q, point)
        point = _add(point, point)
        s >>= 1
    return q


def _decode_point(b: bytes):
    if len(b) != 32:
        return None
    y = int.from_bytes(b, "little")
    sign = y >> 255
    y = (y & ((1 << 255) - 1)) % _P  # like Go, accept a non-canonical y
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None
    if x & 1 != sign:
        if x == 0:
            return None
        x = _P - x
    return (x, y, 1, x * y % _P)


def _encode_point(pt) -> bytes:
    x, y, z, _ = pt
    zi = pow(z, _P - 2, _P)
    x, y = x * zi % _P, y * zi % _P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


_BASE = _decode_point((4 * pow(5, _P - 2, _P) % _P).to_bytes(32, "little"))


def ed25519_verify(public: bytes, message: bytes, signature: bytes) -> bool:
    if len(public) != 32 or len(signature) != 64:
        return False
    a = _decode_point(public)
    if a is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:
        return False
    k = int.from_bytes(hashlib.sha512(signature[:32] + public + message).digest(), "little") % _L
    neg_a = ((_P - a[0]) % _P, a[1], a[2], (_P - a[3]) % _P)
    r = _add(_mul(s, _BASE), _mul(k, neg_a))
    return _encode_point(r) == signature[:32]


def b64url(text: str) -> bytes:
    """Unpadded base64url, canonical only."""
    raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode() != text:
        raise ValueError("not canonical unpadded base64url")
    return raw


# ---------------------------------------------------------------------------
# Endorsement export


EXPORT_FIELDS = {"type", "seq", "message_id", "target", "voter", "public_key", "value", "sponsor", "weight", "created_at",
                 "signed_payload", "signature"}


def verify_record(record: dict, service: str) -> str | None:
    """None if a signed record verifies; otherwise why not. Unsigned and
    legacy records return "unsigned" (weight 0, nothing to verify)."""
    if set(record) - EXPORT_FIELDS:
        return "unknown fields"
    if record.get("signature") is None or record.get("type") == "legacy_vote":
        return "unsigned"
    try:
        key, sig = b64url(record["public_key"]), b64url(record["signature"])
    except (ValueError, KeyError, TypeError):
        return "public_key or signature is not base64url"
    payload = record.get("signed_payload", "")
    if not ed25519_verify(key, payload.encode(), sig):
        return "signature does not verify"
    try:
        envelope = json.loads(payload)
        command = envelope["command"]
    except (ValueError, KeyError, TypeError):
        return "signed_payload is not a command envelope"
    if envelope.get("service") != service:
        return "signed for another service"
    if command.get("public_key") != record["public_key"]:
        return "signed public_key differs"
    if command.get("operation") != record["type"]:
        return "signed operation differs"
    try:
        data = json.loads(command.get("data", ""))
    except ValueError:
        return "signed data is not JSON"
    if not isinstance(data, dict):
        return "signed data is not an object"
    if record["type"] == "vote":
        if command.get("message_id") != record.get("message_id") or data.get("value") != record["value"] or isinstance(data.get("value"), bool):
            return "signed vote differs"
    elif record["type"] == "vouch":
        weight = data.get("weight", 0)
        if set(data) - {"schema", "value", "sponsor", "weight"} or data.get("schema") != 1 or data.get("value") not in (0, 1) \
                or isinstance(data.get("value"), bool) or data.get("value") != record["value"] \
                or bool(data.get("sponsor", False)) != bool(record.get("sponsor")) \
                or isinstance(weight, bool) or not isinstance(weight, int) or weight != record.get("weight", 0) \
                or ("weight" in data and not (1 <= weight <= 50 and data.get("value") == 1)):
            return "signed vouch differs"
    else:
        return "unknown record type"
    return None


def read_export(lines, service: str):
    """Yields (record, problem) for each export line."""
    for n, line in enumerate(lines, 1):
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except ValueError:
            yield {"line": n}, "not JSON"
            continue
        if not isinstance(record, dict):
            yield {"line": n}, "not an object"
            continue
        yield record, verify_record(record, service)


def trust_input(record: dict) -> dict:
    """An export record as a trust input line; zero fields omitted."""
    kind = record["type"]
    if kind == "vote" and record.get("signature") is None:
        kind = "unsigned"
    out = {"type": "endorsement", "seq": record.get("seq", 0), "kind": kind, "voter": record.get("voter", ""),
           "target": record.get("target", ""), "message_id": record.get("message_id", ""), "value": record.get("value", 0),
           "sponsor": bool(record.get("sponsor", False)), "weight": record.get("weight", 0), "created_at": record.get("created_at", 0)}
    return {k: v for k, v in out.items() if k == "type" or v not in (0, "", False)}


# ---------------------------------------------------------------------------



def snapshot_schema(lines) -> int:
    """The snapshot's schema (its meta record's): 1 for the retired versions
    1 to 7, 2 for RFC 0021's (parameter version 8 on)."""
    for line in lines:
        line = line.strip()
        if line.startswith("{") and '"type":"meta"' in line.replace(" ", ""):
            try:
                return json.loads(line).get("schema", 1)
            except json.JSONDecodeError:
                break
    return 1


def compute_any(lines) -> dict:
    """Recomputes a snapshot of either schema."""
    if snapshot_schema(lines) == SNAPSHOT_SCHEMA_V2:
        raws = []
        for n, line in enumerate(lines, 1):
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError as e:
                raise InputError(f"line {n}: {e}") from e
            if not isinstance(raw, dict):
                raise InputError(f"line {n}: not a record")
            raws.append((n, raw))
        return compute_unified(read_snapshot_v2(raws))
    return compute(read_snapshot(lines))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("verify", "endorsements"):
        cmd = sub.add_parser(name)
        cmd.add_argument("export")
        cmd.add_argument("--service", default="swarmmemo.com")
    cmd = sub.add_parser("run")
    cmd.add_argument("snapshot")
    args = parser.parse_args(argv)
    if args.command == "run":
        with open(args.snapshot, encoding="utf-8") as f:
            lines = f.readlines()
        sys.stdout.write(canonical(compute_any(lines)))
        return 0
    counts = {"verified": 0, "unsigned": 0, "failed": 0}
    out = []
    with open(args.export, encoding="utf-8") as f:
        for record, problem in read_export(f, args.service):
            if problem is None:
                counts["verified"] += 1
            elif problem == "unsigned":
                counts["unsigned"] += 1
            else:
                counts["failed"] += 1
                print(f"seq {record.get('seq', record.get('line'))}: {problem}", file=sys.stderr)
                continue
            out.append(record)
    if args.command == "endorsements":
        if counts["failed"]:
            return 1
        for record in out:
            print(canonical(trust_input(record)))
        return 0
    print(canonical(counts))
    return 1 if counts["failed"] else 0


if __name__ == "__main__":
    sys.exit(main())
