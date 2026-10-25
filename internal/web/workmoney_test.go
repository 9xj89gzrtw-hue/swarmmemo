package web

import (
	"net/http/httptest"
	"strings"
	"testing"

	"swarmmemo/internal/board"
)

// Each accepted result's money on /work/ID (C589): credits paid, USDC owed
// since a time, or paid with its transaction linked to the explorer.
func TestWorkSSRShowsResultMoney(t *testing.T) {
	hash := "0x" + strings.Repeat("ab", 32)
	worker := board.AgentRef{ID: strings.Repeat("3", 64), Handle: "helper"}
	item := board.Work{ID: webWorkID, Room: "lobby", Title: "Find bugs", State: "accepted", StoredState: "accepted", Requester: board.AgentRef{ID: strings.Repeat("2", 64)},
		Capabilities: []string{}, Deadline: 1789171200, Results: []board.WorkAcceptedResult{
			{ResultID: strings.Repeat("c", 32), WorkID: strings.Repeat("c", 32), Worker: worker, AcceptedAt: 1789171000,
				Money: &board.WorkResultMoney{Credits: 300, USDC: &board.WorkResultUSDC{State: board.WorkUSDCOwed, Amount: "0.1", Since: 1789171050, Note: "announced extra"}}},
			{ResultID: strings.Repeat("d", 32), WorkID: strings.Repeat("d", 32), Worker: worker, AcceptedAt: 1789170000,
				Money: &board.WorkResultMoney{USDC: &board.WorkResultUSDC{State: board.WorkUSDCPaid, Amount: "0.2", TxHash: hash, TxURL: board.USDCTxURL("eip155:8453", hash), PaidAt: 1789171100}}},
		}}
	s := &testService{execute: func(c board.Command) (board.Result, error) {
		switch c.Operation {
		case "room.get":
			return board.Result{OK: true, Room: &board.Room{Name: c.Room, Visibility: "public"}}, nil
		case "work.get":
			return board.Result{OK: true, Data: map[string]any{"work": item}}, nil
		case "work.history":
			return board.Result{OK: true, Data: map[string]any{"work_id": item.ID, "transitions": []board.WorkTransition{}}}, nil
		}
		return board.Result{OK: true}, nil
	}}
	w := httptest.NewRecorder()
	Handler(s).ServeHTTP(w, httptest.NewRequest("GET", "/work/"+webWorkID, nil))
	if w.Code != 200 {
		t.Fatalf("status %d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{"300 credits paid · 0.1 USDC <span class=\"pay-unpaid\">owed since 2026-09-11", "(announced extra)",
		"0.2 USDC paid 2026-09-11", `<a href="https://basescan.org/tx/` + hash + `" rel="nofollow noopener">`} {
		if !strings.Contains(body, want) {
			t.Errorf("work page misses %q", want)
		}
	}
}
