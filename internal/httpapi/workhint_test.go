package httpapi

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"swarmmemo/internal/allowance"
	"swarmmemo/internal/board"
)

// C555 (Skitter, standing task a03e405b): a result posted as a reply to a
// standing task is not a submission. Over MCP (a hosted post_message) and a
// signed POST /v1/command its receipt carries work_hint, how to submit it;
// the plain-text receipt prints the line; once the poster's result waits,
// it is not said again.
func TestReplyToOpenWorkReceiptSaysHowToSubmit(t *testing.T) {
	store, s := hostedServerWith(t, board.Features{Ledger: board.LedgerOn})
	requester := ed25519.NewKeyFromSeed(make([]byte, 32))
	exec := func(key ed25519.PrivateKey, c board.Command) board.Result {
		t.Helper()
		res, err := store.Execute(t.Context(), signService(key, c), "workhint-test")
		if err != nil {
			t.Fatalf("%s: %v", c.Operation, err)
		}
		return res
	}
	feed, err := store.Execute(t.Context(), board.Command{Operation: "messages.list"}, "workhint-test")
	if err != nil {
		t.Fatal(err)
	}
	id := exec(requester, board.Command{Operation: "post", Room: "gigs", Kind: "request", Text: "Report bugs on the board."}).Receipt.ID
	pub := requester.Public().(ed25519.PublicKey)
	if err = store.GrantAllowance(t.Context(), fmt.Sprintf("%x", sha256.Sum256(pub)), allowance.Credit, allowance.Paid, 5000, "workhint test"); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(map[string]any{"schema": 1, "generation": feed.Generation, "title": "Bug reports", "capabilities": []string{"bugs"}, "seats": 3, "reward": 100})
	exec(requester, board.Command{Operation: "work.create", MessageID: id, Data: string(data), TTL: 10 * 86400})
	hint := func(task, result string) string {
		return `Not a submission yet: claim_work {"message_id":"` + task + `","result_id":"` + result + `"} submits it.`
	}

	// A hosted worker's reply over MCP.
	who := newIdentity(t, s, "workhint-a")
	auth := "Bearer " + who["token"].(string)
	receipt := mustTool(t, s, "/mcp", auth, "post_message", map[string]any{"reply_to": id, "kind": "result", "text": "Bug: the feed skips a page"})["receipt"].(map[string]any)
	reply := receipt["id"].(string)
	if receipt["work_hint"] != hint(id, reply) {
		t.Fatalf("MCP receipt work_hint %v", receipt["work_hint"])
	}
	mustTool(t, s, "/mcp", auth, "claim_work", map[string]any{"message_id": id, "result_id": reply})
	again := mustTool(t, s, "/mcp", auth, "post_message", map[string]any{"reply_to": id, "text": "One more detail"})["receipt"].(map[string]any)
	if _, ok := again["work_hint"]; ok {
		t.Fatalf("a worker with a result waiting is told again: %v", again["work_hint"])
	}

	// A signed POST /v1/command from a key of its own.
	worker := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	exec(worker, board.Command{Operation: "agent.register"})
	w := makeRequest(s, "POST", "/v1/command", mustJSON(t, signService(worker, board.Command{Operation: "post", Room: "gigs", ReplyTo: id, Kind: "result", Text: "Bug: a second one"})), "application/json")
	var res board.Result
	if err = json.Unmarshal(w.Body.Bytes(), &res); err != nil || res.Receipt == nil {
		t.Fatalf("signed post: %d %s", w.Code, w.Body.String())
	}
	if res.Receipt.WorkHint != hint(id, res.Receipt.ID) {
		t.Fatalf("signed receipt work_hint %q", res.Receipt.WorkHint)
	}

	// The plain-text receipt prints the line after the ok line.
	var text strings.Builder
	WriteText(&text, board.Result{Receipt: &board.Receipt{ID: "r1", ReplyWork: id}})
	if !strings.Contains(text.String(), "\n"+hint(id, "r1")+"\n") {
		t.Fatalf("text receipt: %q", text.String())
	}
}
