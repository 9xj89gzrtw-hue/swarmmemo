package services

// Operator vets of bundler tools (C570). A tools_search hit carries the
// bundler's own vetting flag; swarmmemo x402 vet tool:ID makes a tool the
// bundler has not vetted callable anyway, through the same call path and
// every other guardrail (HTTPS, max_price, the denylist, never adult or
// gambling). The vet is bound to what the operator saw in the tool's live
// descriptor and probe: its host, its method and its price. A descriptor
// that later names another host or method, or a price above the vetted one,
// drops the vet until the operator vets it again.
//
// Vets live in x402_vetted beside the catalogue's (no schema change): id
// tool:NAME (the public id), url https://HOST/, method, state, reason
// operator, and pay_to holding the vetted price in micro-USD as a decimal
// integer (a tool's recipient is the bundler's business). No catalogue id
// starts with "tool:", and no pay_to of a tool row parses as an address.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"swarmmemo/internal/allowance"
)

// toolVet is an operator vet of a bundler tool: what it is bound to.
type toolVet struct {
	host, method string
	price        int64 // micro-USD: the most the tool may be priced
}

// holds says whether the vet still applies to a tool seen with this host,
// method and price; a field not known yet (a search hit has no descriptor)
// does not break it. The call's gate uses holdsLive.
func (v toolVet) holds(host, method string, price int64, priced bool) bool {
	return (host == "" || host == v.host) && (method == "" || method == v.method) && (!priced || price <= v.price)
}

// holdsLive is holds against the live descriptor and probe, where every
// field must be known.
func (v toolVet) holdsLive(host, method string, price int64, priced bool) bool {
	return host == v.host && method == v.method && priced && price <= v.price
}

// neverVetted says whether no operator vet may make a tool of category c
// callable.
func neverVetted(c string) bool { return c == "adult" || c == "gambling" }

// toolVets reads the operator vets of tools (upstream ids), keyed by
// upstream id.
func toolVets(ctx context.Context, q allowance.Querier, tools ...string) (map[string]toolVet, error) {
	out := map[string]toolVet{}
	if len(tools) == 0 {
		return out, nil
	}
	byPublic := make(map[string]string, len(tools))
	args := make([]any, 0, len(tools))
	for _, t := range tools {
		id := bundlerToolID(t)
		if _, dup := byPublic[id]; !dup {
			args = append(args, id)
		}
		byPublic[id] = t
	}
	rows, err := queryAll(ctx, q, func(r *sql.Rows) ([4]string, error) {
		var v [4]string
		return v, r.Scan(&v[0], &v[1], &v[2], &v[3])
	}, "SELECT id,url,method,pay_to FROM x402_vetted WHERE state='vetted' AND reason=? AND id IN (?"+strings.Repeat(",?", len(args)-1)+")",
		append([]any{x402VetByOperator}, args...)...)
	if err != nil {
		return out, err
	}
	for _, r := range rows {
		price, err := strconv.ParseInt(r[3], 10, 64)
		host := strings.TrimSuffix(strings.TrimPrefix(r[1], "https://"), "/")
		if err != nil || price <= 0 || host == "" || r[2] == "" {
			continue
		}
		out[byPublic[r[0]]] = toolVet{host: host, method: r[2], price: price}
	}
	return out, nil
}

// operatorVetted says whether tool has an operator vet that holds for what
// is known of it.
func operatorVetted(ctx context.Context, q allowance.Querier, tool, host string) bool {
	vets, err := toolVets(ctx, q, tool)
	v, ok := vets[tool]
	return err == nil && ok && v.holds(host, "", 0, false)
}

// liveVet says whether tool's operator vet holds against its live
// descriptor d and its price now; read fresh, so an unvet applies to the
// next call.
func (x *x402) liveVet(ctx context.Context, tool string, d bundlerDescriptor, price int64, priced bool) bool {
	vets, err := toolVets(ctx, x.db, tool)
	v, ok := vets[tool]
	return err == nil && ok && !neverVetted(d.category) && httpsURL(d.url) && v.holdsLive(d.host, d.method, price, priced)
}

// httpsURL says whether raw is an https URL with a host.
func httpsURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Hostname() != ""
}

// ToolVetting is what swarmmemo x402 vet tool:ID and unvet report.
type ToolVetting struct {
	ID, Title, Host, Method, Category string
	Price, Cost                       int64 // micro-USD: the vetted price; the most a call of it pays, fees included
	BundlerVetted                     bool
	Vetted                            bool
}

// toolVetName is the tool name in an operator's tool:ID.
func toolVetName(id string) (string, error) {
	name, ok := bundlerResource(id)
	if !ok || !bundlerToolRE.MatchString(name) {
		return "", fmt.Errorf("x402: %q is not a tool id (tool:NAME, as tools_search shows it)", id)
	}
	return name, nil
}

// VetTool vets a bundler tool (swarmmemo x402 vet tool:ID): it reads the
// tool's live descriptor and probe, refuses what no vet may make callable,
// and records the vet bound to the host, method and price it read. It
// applies at once (every call reads it before it pays). Operator only.
func (e *Engine) VetTool(ctx context.Context, id string, now int64) (ToolVetting, error) {
	p, err := e.cfg.Registry.Lookup("x402")
	x, ok := p.(*x402)
	if err != nil || !ok || x.fr == nil || !x.fr.b.Ready() {
		return ToolVetting{}, errors.New("x402: vetting a tool needs the open tool index on (SERVICES with x402, X402_CONFIG with bundlers.frames.open and its key): the vet binds to the tool's live descriptor")
	}
	return x.vetTool(ctx, id, now)
}

func (x *x402) vetTool(ctx context.Context, id string, now int64) (ToolVetting, error) {
	name, err := toolVetName(id)
	if err != nil {
		return ToolVetting{}, err
	}
	tool, row, known, err := bundlerLookup(ctx, x.db, name, now)
	if err != nil {
		return ToolVetting{}, err
	}
	v := ToolVetting{ID: bundlerToolID(tool), BundlerVetted: row.vetted}
	if !known {
		return v, fmt.Errorf("x402: no tools_search returned %s in the last 30 days; find it with tools_search first", v.ID)
	}
	d, err := x.bundlerDescriptorOf(ctx, tool)
	if err != nil {
		return v, fmt.Errorf("x402: reading %s's descriptor: %w", v.ID, err)
	}
	pr, err := x.bundlerProbeOf(ctx, tool)
	if err != nil {
		return v, fmt.Errorf("x402: probing %s: %w", v.ID, err)
	}
	price, priced := pr.price, pr.priced
	if !priced {
		price, priced = d.price, d.priced
	}
	v.Title, v.Host, v.Method, v.Category, v.Price = d.title, d.host, d.method, d.category, price
	if v.Category == "" || v.Category == "other" {
		v.Category = row.category
	}
	for _, c := range []string{d.category, row.category} {
		if neverVetted(c) {
			return v, fmt.Errorf("x402: %s is in category %s; adult and gambling tools are never vetted", v.ID, c)
		}
	}
	switch {
	case !httpsURL(d.url) || d.host == "":
		return v, fmt.Errorf("x402: %s's endpoint is not HTTPS with a host (%q); only HTTPS tools are vetted", v.ID, d.url)
	case d.method == "":
		return v, fmt.Errorf("x402: %s's descriptor names no method; nothing to bind a vet to", v.ID)
	case !priced:
		return v, fmt.Errorf("x402: %s has no price in its probe or descriptor; nothing to bind a vet to", v.ID)
	case x.fr.denied(d.category, d.host) || x.fr.denied(row.category, ""):
		return v, fmt.Errorf("x402: %s (host %s, category %s) is on the operator's denylist", v.ID, d.host, v.Category)
	case x.fr.overCap(price):
		return v, fmt.Errorf("x402: %s is priced %s USD, over tools.max_price %s", v.ID, formatUnits(price, 6), formatUnits(x.fr.cfg.MaxPrice, 6))
	case !pr.live || !pr.payable:
		return v, fmt.Errorf("x402: %s's probe says it is not live and payable; vet it when it is", v.ID)
	}
	v.Cost, v.Vetted = bundlerCost(price), true
	_, err = x.db.ExecContext(ctx, `INSERT INTO x402_vetted(id,url,method,pay_to,state,reason,changed_at) VALUES(?,?,?,?,'vetted',?,?)
ON CONFLICT(id) DO UPDATE SET url=excluded.url, method=excluded.method, pay_to=excluded.pay_to, state=excluded.state, reason=excluded.reason, changed_at=excluded.changed_at`,
		v.ID, "https://"+d.host+"/", d.method, strconv.FormatInt(price, 10), x402VetByOperator, now)
	return v, err
}

// UnvetTool withdraws the operator's vet of a bundler tool (swarmmemo x402
// unvet tool:ID): it needs no network and applies at once. The bundler's own
// vetting flag is untouched.
func UnvetTool(ctx context.Context, db *sql.DB, id string, now int64) (ToolVetting, error) {
	name, err := toolVetName(id)
	if err != nil {
		return ToolVetting{}, err
	}
	v := ToolVetting{ID: bundlerToolID(name)}
	res, err := db.ExecContext(ctx, "UPDATE x402_vetted SET state='unvetted', reason=?, changed_at=? WHERE id=? AND state='vetted'", x402VetByOperator, now, v.ID)
	if err != nil {
		return v, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return v, fmt.Errorf("x402: %s has no operator vet to withdraw", v.ID)
	}
	return v, nil
}
