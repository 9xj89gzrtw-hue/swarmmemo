package services

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeUSDCRPC is a chain for the read-back: authorizationState answers used
// for the nonces in used, and AuthorizationUsed's log names tx.
type fakeUSDCRPC struct {
	mu    sync.Mutex
	used  map[string]bool // nonce (0x-hex) -> used on chain
	calls int             // eth_call requests
	tx    string
}

func (f *fakeUSDCRPC) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	var req struct {
		Method string            `json:"method"`
		Params []json.RawMessage `json:"params"`
	}
	_ = json.Unmarshal(raw, &req)
	f.mu.Lock()
	defer f.mu.Unlock()
	var result any
	switch req.Method {
	case "eth_call":
		f.calls++
		var call struct{ To, Data string }
		_ = json.Unmarshal(req.Params[0], &call)
		// selector (4 bytes) + authorizer word + nonce word
		nonce := "0x" + call.Data[len(call.Data)-64:]
		word := strings.Repeat("0", 63) + "0"
		if f.used[nonce] && strings.EqualFold(call.To, testUSDC) && strings.Contains(strings.ToLower(call.Data), strings.ToLower(x402TestPayer[2:])) {
			word = strings.Repeat("0", 63) + "1"
		}
		result = "0x" + word
	case "eth_blockNumber":
		result = "0x1000"
	case "eth_getLogs":
		result = []any{map[string]any{"address": strings.ToLower(testUSDC), "transactionHash": f.tx, "removed": false}}
	default:
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "result": result})
}

// x402TestPayer is x402TestKey's address.
const x402TestPayer = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"

// lateHarness is the x402 harness with a fake chain wired into the provider.
func lateHarness(t *testing.T, fake *fakeX402) (*x402Harness, *x402, *fakeUSDCRPC) {
	t.Helper()
	h := newX402Harness(t, fake, `{}`)
	p, _ := h.engine.cfg.Registry.Lookup("x402")
	x := p.(*x402)
	rpc := &fakeUSDCRPC{used: map[string]bool{}, tx: "0x" + strings.Repeat("cd", 32)}
	srv := httptest.NewServer(rpc)
	t.Cleanup(srv.Close)
	usdc, _ := ParseEVMAddress(testUSDC)
	chain := &USDCChain{Network: "eip155:8453", Asset: usdc, Confirmations: 1}
	chain.UseTestRPC(srv.Client(), srv.URL)
	x.late.chain = chain
	return h, x, rpc
}

func (h *x402Harness) reimbursed() []int64 {
	entries, err := h.meter.Entries(context.Background(), h.db)
	if err != nil {
		h.t.Fatal(err)
	}
	var out []int64
	for _, e := range entries {
		if e.Kind == "reimburse" {
			out = append(out, e.Units)
		}
	}
	return out
}

func (h *x402Harness) validBefore() int64 {
	var v int64
	if err := h.db.QueryRow("SELECT valid_before FROM x402_payments").Scan(&v); err != nil {
		h.t.Fatal(err)
	}
	return v
}

// A seller answering 200 without a successful settlement (success false, or
// no settlement header): the answer and a receipt come back, the agent is
// charged, and the payment stays unknown, its receipt saying why (C534).
func TestX402UnconfirmedSettlementStaysCharged(t *testing.T) {
	for _, mode := range []string{"false", "none"} {
		t.Run(mode, func(t *testing.T) {
			h := newX402Harness(t, &fakeX402{price: 1500, settle: mode}, `{}`)
			out, err := h.call(testSubject, `{"resource":"price","query":{"ids":"bitcoin","vs":"usd"}}`, creditsFor(10000))
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := json.Marshal(out)
			var got struct {
				Call   CallRecord
				Result x402Out
			}
			if err := json.Unmarshal(raw, &got); err != nil {
				t.Fatal(err)
			}
			if got.Call.State != "done" || got.Call.Cost != creditsFor(1500) || got.Result.Encoding != "json" {
				t.Fatalf("call: %s", raw)
			}
			if p := got.Result.Payment; p == nil || p.SettlementStatus != "unconfirmed" || p.Note != X402UnconfirmedNote || p.Transaction != "" {
				t.Fatalf("receipt: %s", raw)
			}
			if h.charged() != creditsFor(1500) {
				t.Fatalf("charged %d", h.charged())
			}
			pays := h.payments()
			if len(pays) != 1 || pays[0]["state"] != "unknown" || pays[0]["reason"] != "settlement_unconfirmed" || pays[0]["tx"] != "" {
				t.Fatalf("payments %v", pays)
			}
		})
	}
	// A confirmed settlement keeps its receipt as it was: no status, no note.
	h := newX402Harness(t, &fakeX402{price: 1500}, `{}`)
	out, err := h.call(testSubject, `{"resource":"price"}`, creditsFor(10000))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(out)
	if strings.Contains(string(raw), "settlement_status") || strings.Contains(string(raw), X402UnconfirmedNote) {
		t.Fatalf("confirmed receipt: %s", raw)
	}
}

// Once the authorization expired unused, the charge is paid back once and
// the row fails; before expiry nothing is read.
func TestX402LateSettlementExpiredUnusedRefunds(t *testing.T) {
	h, x, rpc := lateHarness(t, &fakeX402{price: 1500, settle: "false"})
	if _, err := h.call(testSubject, `{"resource":"price"}`, creditsFor(10000)); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	vb := h.validBefore()
	if n, err := x.reconcileLate(ctx, h.now, vb); err != nil || n != 0 || rpc.calls != 0 {
		t.Fatalf("before expiry: %d %v, %d reads", n, err, rpc.calls)
	}
	if n, err := x.reconcileLate(ctx, h.now, vb+x402LateMargin); err != nil || n != 0 || rpc.calls != 0 {
		t.Fatalf("within the margin: %d %v, %d reads", n, err, rpc.calls)
	}
	if pays := h.payments(); pays[0]["state"] != "unknown" || len(h.reimbursed()) != 0 {
		t.Fatalf("touched before expiry: %v %v", pays, h.reimbursed())
	}
	after := vb + x402LateMargin + 1
	if n, err := x.reconcileLate(ctx, h.now, after); err != nil || n != 1 {
		t.Fatalf("after expiry: %d %v", n, err)
	}
	pays := h.payments()
	if pays[0]["state"] != "failed" || pays[0]["reason"] != "settlement_expired_unused" {
		t.Fatalf("payments %v", pays)
	}
	if got := h.reimbursed(); len(got) != 1 || got[0] != creditsFor(1500) {
		t.Fatalf("reimbursed %v", got)
	}
	// Again: nothing left to read, nothing paid back twice.
	if n, err := x.reconcileLate(ctx, h.now, after+3600); err != nil || n != 0 {
		t.Fatalf("second pass: %d %v", n, err)
	}
	if got := h.reimbursed(); len(got) != 1 {
		t.Fatalf("reimbursed twice: %v", got)
	}
	// The row now counts in no cap: a failed payment never moved money.
	var counted int64
	_ = h.db.QueryRow("SELECT COALESCE(SUM(amount),0) FROM x402_payments WHERE state<>'failed'").Scan(&counted)
	if counted != 0 {
		t.Fatalf("still counted %d", counted)
	}
	// Even with the row put back, the meter pays a hold back once.
	if _, err := h.db.Exec("UPDATE x402_payments SET state='unknown', reason='settlement_unconfirmed'"); err != nil {
		t.Fatal(err)
	}
	if _, err := x.reconcileLate(ctx, h.now, after); err != nil {
		t.Fatal(err)
	}
	if got := h.reimbursed(); len(got) != 1 {
		t.Fatalf("reimbursed twice: %v", got)
	}
}

// A seller that settled after all: the row is paid, with the transaction its
// AuthorizationUsed event names, and the charge stands.
func TestX402LateSettlementUsedIsPaid(t *testing.T) {
	h, x, rpc := lateHarness(t, &fakeX402{price: 1500, settle: "none"})
	if _, err := h.call(testSubject, `{"resource":"price"}`, creditsFor(10000)); err != nil {
		t.Fatal(err)
	}
	rpc.used[h.payments()[0]["nonce"].(string)] = true
	if n, err := x.reconcileLate(context.Background(), h.now, h.validBefore()+x402LateMargin+1); err != nil || n != 1 {
		t.Fatalf("reconcile: %d %v", n, err)
	}
	pays := h.payments()
	if pays[0]["state"] != "paid" || pays[0]["reason"] != "settled_late" || pays[0]["tx"] != rpc.tx {
		t.Fatalf("payments %v", pays)
	}
	if len(h.reimbursed()) != 0 || h.charged() != creditsFor(1500) {
		t.Fatalf("reimbursed %v charged %d", h.reimbursed(), h.charged())
	}
}

// Other unknown rows (no answer at all, already refunded) are never read
// back, and nothing runs without a chain reader.
func TestX402LateSettlementLeavesOtherRows(t *testing.T) {
	h, x, rpc := lateHarness(t, &fakeX402{price: 1500, settle: "false"})
	if _, err := h.call(testSubject, `{"resource":"price"}`, creditsFor(10000)); err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.Exec("UPDATE x402_payments SET reason='no_response'"); err != nil {
		t.Fatal(err)
	}
	if n, err := x.reconcileLate(context.Background(), h.now, h.validBefore()+86400); err != nil || n != 0 || rpc.calls != 0 {
		t.Fatalf("no_response row read back: %d %v %d", n, err, rpc.calls)
	}
	if _, err := h.db.Exec("UPDATE x402_payments SET reason='settlement_unconfirmed'"); err != nil {
		t.Fatal(err)
	}
	x.late.chain = nil
	if n, err := x.reconcileLate(context.Background(), h.now, h.validBefore()+86400); err != nil || n != 0 || h.payments()[0]["state"] != "unknown" {
		t.Fatalf("without a chain: %d %v %v", n, err, h.payments())
	}
}
