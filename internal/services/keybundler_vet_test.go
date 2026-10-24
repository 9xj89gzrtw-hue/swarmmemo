package services

import (
	"context"
	"strings"
	"testing"
)

// bundlerOf is the harness's x402 provider.
func bundlerOf(t *testing.T, h *x402Harness) *x402 {
	t.Helper()
	p, err := h.engine.cfg.Registry.Lookup("x402")
	if err != nil {
		t.Fatal(err)
	}
	return p.(*x402)
}

// forget empties the descriptor and probe caches, as an hour passing would.
func (x *x402) forget() {
	x.fr.mu.Lock()
	x.fr.descriptors, x.fr.probes = ttlCache[bundlerDescriptor]{}, ttlCache[bundlerProbe]{}
	x.fr.mu.Unlock()
}

// TestBundlerOperatorVet: x402 vet tool:ID makes a tool the bundler has not
// vetted callable, shows it as vetted_by operator with the bundler's own
// flag kept, and x402 unvet withdraws it at the next call.
func TestBundlerOperatorVet(t *testing.T) {
	h, _ := newBundlerHarness(t, "", "")
	ctx := context.Background()
	call := func() error {
		_, err := h.call(testSubject, `{"resource":"tool:`+toolUnvet+`"}`, creditsFor(20000))
		return err
	}
	if _, err := h.engine.VetTool(ctx, "tool:"+toolUnvet, h.now); err == nil || !strings.Contains(err.Error(), "tools_search first") {
		t.Fatalf("vet before any search: %v", err)
	}
	if _, err := h.bundlerRead(testSubject, "tools_search", `{"query":"weather"}`); err != nil {
		t.Fatal(err)
	}
	if err := call(); errCode(err) != "tool_unvetted" {
		t.Fatalf("before the vet: %v", err)
	}
	v, err := h.engine.VetTool(ctx, "tool:"+toolUnvet, h.now)
	if err != nil || !v.Vetted || v.ID != "tool:"+toolUnvet || v.Host != "unvetted.example.com" || v.Method != "POST" || v.Price != 2000 || v.Cost != bundlerCost(2000) || v.BundlerVetted {
		t.Fatalf("vet %+v %v", v, err)
	}
	page, err := h.bundlerRead(testSubject, "tools_search", `{"query":"weather"}`)
	if err != nil {
		t.Fatal(err)
	}
	hit := hitsByID(page)["tool:"+toolUnvet]
	if hit["vetted"] != true || hit["vetted_by"] != "operator" || hit["bundler_vetted"] != false || hit["callable"] != true {
		t.Fatalf("vetted hit %v", hit)
	}
	if ok := hitsByID(page)["tool:"+toolOK]; ok["vetted_by"] != nil || ok["bundler_vetted"] != nil {
		t.Fatalf("a bundler-vetted hit gained operator fields: %v", ok)
	}
	tool, err := h.bundlerRead(testSubject, "tools_get", `{"id":"tool:`+toolUnvet+`"}`)
	if err != nil || tool["vetted"] != true || tool["vetted_by"] != "operator" || tool["callable"] != true {
		t.Fatalf("tools_get %v %v", tool, err)
	}
	if err := call(); err != nil {
		t.Fatalf("operator-vetted call: %v", err)
	}
	if v, err := UnvetTool(ctx, h.db, "tool:"+toolUnvet, h.now); err != nil || v.Vetted {
		t.Fatalf("unvet %+v %v", v, err)
	}
	if err := call(); errCode(err) != "tool_unvetted" {
		t.Fatalf("after the unvet: %v", err)
	}
	if _, err := UnvetTool(ctx, h.db, "tool:"+toolUnvet, h.now); err == nil {
		t.Fatal("a second unvet must say there is no vet")
	}
	for _, id := range []string{"tool:", "weather", "tool:a/b"} {
		if _, err := UnvetTool(ctx, h.db, id, h.now); err == nil || !strings.Contains(err.Error(), "not a tool id") {
			t.Errorf("unvet %q: %v", id, err)
		}
	}
}

// TestBundlerOperatorVetBinding: the vet holds only for the host, method and
// price the operator saw; another host or method, or a higher price, drops
// it until the operator vets again, and a lower price keeps it.
func TestBundlerOperatorVetBinding(t *testing.T) {
	h, api := newBundlerHarness(t, "", "")
	ctx := context.Background()
	x := bundlerOf(t, h)
	call := func() error {
		_, err := h.call(testSubject, `{"resource":"tool:`+toolUnvet+`"}`, creditsFor(20000))
		return err
	}
	if _, err := h.bundlerRead(testSubject, "tools_search", `{"query":"weather"}`); err != nil {
		t.Fatal(err)
	}
	if _, err := h.engine.VetTool(ctx, "tool:"+toolUnvet, h.now); err != nil {
		t.Fatal(err)
	}
	original := api.tools[toolUnvet]
	for _, c := range []struct {
		name, descriptor, probe string
		want                    string
	}{
		{"another host", bundlerDescriptorJSON(toolUnvet, "elsewhere.example.com", "Weather "+toolUnvet), "", "tool_unvetted"},
		{"another method", strings.Replace(original, `"method":"POST"`, `"method":"GET"`, 1), "", "tool_unvetted"},
		{"a higher price", original, `{"id":"` + toolUnvet + `","live":true,"price_usd":0.003,"payable":true}`, "tool_unvetted"},
		{"a lower price", original, `{"id":"` + toolUnvet + `","live":true,"price_usd":0.001,"payable":true}`, ""},
		{"as vetted", original, "", ""},
	} {
		api.mu.Lock()
		api.tools[toolUnvet] = c.descriptor
		delete(api.probes, toolUnvet)
		if c.probe != "" {
			api.probes[toolUnvet] = c.probe
		}
		api.mu.Unlock()
		x.forget()
		if err := call(); errCode(err) != c.want && !(c.want == "" && err == nil) {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
		tool, err := h.bundlerRead(testSubject, "tools_get", `{"id":"tool:`+toolUnvet+`"}`)
		if err != nil || (tool["vetted_by"] == "operator") != (c.want == "") {
			t.Errorf("%s: tools_get %v %v", c.name, tool, err)
		}
	}
	// A rise vetted again holds again.
	api.mu.Lock()
	api.probes[toolUnvet] = `{"id":"` + toolUnvet + `","live":true,"price_usd":0.003,"payable":true}`
	api.mu.Unlock()
	x.forget()
	if err := call(); errCode(err) != "tool_unvetted" {
		t.Fatalf("raised price: %v", err)
	}
	if v, err := h.engine.VetTool(ctx, "tool:"+toolUnvet, h.now); err != nil || v.Price != 3000 {
		t.Fatalf("vet again %+v %v", v, err)
	}
	if err := call(); err != nil {
		t.Fatalf("vetted again: %v", err)
	}
}

// TestBundlerOperatorVetRefusals: no vet makes an adult or gambling tool, a
// denied one, one over max_price or one without HTTPS callable.
func TestBundlerOperatorVetRefusals(t *testing.T) {
	h, api := newBundlerHarness(t, "", `{"domains":["evil.example.net"]}`)
	ctx := context.Background()
	api.tools[toolUnvet] = bundlerDescriptorJSON(toolUnvet, "unvetted.example.com", "Casino betting odds")
	api.tools[toolDead] = strings.Replace(api.tools[toolDead], "https://dead", "http://dead", 1)
	api.probes[toolDead] = `{"id":"` + toolDead + `","live":true,"price_usd":0.002,"payable":true}`
	if _, err := h.bundlerRead(testSubject, "tools_search", `{"query":"weather"}`); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ tool, want string }{
		{toolUnvet, "category gambling; adult and gambling tools are never vetted"},
		{toolDenied, "denylist"},
		{toolPricey, "over tools.max_price 0.02"},
		{toolDead, "not HTTPS"},
	} {
		v, err := h.engine.VetTool(ctx, "tool:"+c.tool, h.now)
		if err == nil || !strings.Contains(err.Error(), c.want) || v.Vetted {
			t.Errorf("%s: %v, want %q", c.tool, err, c.want)
		}
	}
	var n int
	if err := h.db.QueryRow("SELECT count(*) FROM x402_vetted").Scan(&n); err != nil || n != 0 {
		t.Fatalf("a refused vet was recorded: %d %v", n, err)
	}
	// A row written by hand still never makes a gambling tool callable.
	if _, err := h.db.Exec(`INSERT INTO x402_vetted(id,url,method,pay_to,state,reason,changed_at) VALUES(?,?,?,?,'vetted',?,?)`,
		"tool:"+toolUnvet, "https://unvetted.example.com/", "POST", "2000", x402VetByOperator, h.now); err != nil {
		t.Fatal(err)
	}
	if _, err := h.call(testSubject, `{"resource":"tool:`+toolUnvet+`"}`, creditsFor(20000)); errCode(err) != "tool_unvetted" {
		t.Fatalf("hand-vetted gambling tool: %v", err)
	}
}

// TestBundlerCostCapFitsMaxPrice: max_cost is derived from max_price and
// the bundler's fees, so a tool priced exactly max_price ($0.02, $0.028 a
// call with the fees) is callable, and one priced over it is not.
func TestBundlerCostCapFitsMaxPrice(t *testing.T) {
	h, api := newBundlerHarness(t, "", "")
	api.probes[toolOK] = `{"id":"` + toolOK + `","live":true,"price_usd":0.02,"payable":true}`
	page, err := h.bundlerRead(testSubject, "tools_search", `{"query":"weather"}`)
	if err != nil {
		t.Fatal(err)
	}
	maxCost := creditsFor(bundlerCost(20000))
	if tools := page["tools"].(map[string]any); tools["max_price"] != "0.02" || tools["max_cost"] != float64(maxCost) || maxCost != 30900 {
		t.Fatalf("tools block %v, want max_cost %d", tools, maxCost)
	}
	if _, err := h.call(testSubject, `{"resource":"tool:`+toolOK+`"}`, maxCost); err != nil {
		t.Fatalf("a tool priced max_price: %v", err)
	}
	if api.lastInvoke["max_usd"] != 0.028 {
		t.Fatalf("max_usd %v, want the cost with fees", api.lastInvoke["max_usd"])
	}
	tool, err := h.bundlerRead(testSubject, "tools_get", `{"id":"tool:`+toolOK+`"}`)
	if err != nil || tool["callable"] != true || tool["cost"] != float64(maxCost) {
		t.Fatalf("tools_get %v %v", tool, err)
	}
	api.mu.Lock()
	api.probes[toolOK] = `{"id":"` + toolOK + `","live":true,"price_usd":0.020001,"payable":true}`
	api.mu.Unlock()
	bundlerOf(t, h).forget()
	if _, err := h.call(testSubject, `{"resource":"tool:`+toolOK+`"}`, maxCost); errCode(err) != "tool_price_over_cap" {
		t.Fatalf("over max_price: %v", err)
	}
}
