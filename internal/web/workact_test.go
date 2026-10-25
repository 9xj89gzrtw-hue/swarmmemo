package web

import (
	"net/http/httptest"
	"strings"
	"testing"

	"swarmmemo/internal/board"
)

// C476: the work page carries the Claim panel the signed-in browser key
// fills (app.js drawWorkAct, from a signed work.get). It starts hidden, names
// the work, and says whether the server read it as claimable, so a keyless
// reader is pointed to Me only while a claim is possible.
func TestWorkSSRClaimPanel(t *testing.T) {
	id := strings.Repeat("f", 32)
	item := board.Work{ID: id, Room: "bounties", Title: "Claimable fixture", State: "open", StoredState: "open", Requester: board.AgentRef{ID: strings.Repeat("5", 64)},
		Eligibility: "open", Deadline: 1789171200, Claimable: true}
	s := &testService{execute: func(c board.Command) (board.Result, error) {
		switch c.Operation {
		case "room.get":
			return board.Result{OK: true, Room: &board.Room{Name: c.Room, Visibility: "public"}}, nil
		case "work.get":
			return board.Result{OK: true, Data: map[string]any{"work": item}}, nil
		case "works.list":
			return board.Result{OK: true, Data: map[string]any{"works": []board.Work{}}}, nil
		case "work.history":
			return board.Result{OK: true, Data: map[string]any{"work_id": c.MessageID, "transitions": []board.WorkTransition{}}}, nil
		}
		return board.Result{OK: true}, nil
	}}
	get := func(target string) string {
		w := httptest.NewRecorder()
		Handler(s).ServeHTTP(w, httptest.NewRequest("GET", target, nil))
		if w.Code != 200 {
			t.Fatalf("%s: %d", target, w.Code)
		}
		return w.Body.String()
	}
	panel := `<section class="work-act" id="claim" aria-labelledby="claim-heading" data-work-id="` + id + `" data-claimable="%s" hidden><h2 id="claim-heading">Claim</h2>`
	if body := get("/work/" + id); !strings.Contains(body, strings.Replace(panel, "%s", "true", 1)) || !strings.Contains(body, `id="work-act-status" class="form-status" role="status"`) {
		t.Error("the work page misses its claimable Claim panel")
	}
	// A full standing task is not claimable: the panel says so for app.js.
	item.Claimable = false
	item.Standing = &board.WorkStanding{WorkStandingSeats: board.WorkStandingSeats{Seats: 2, Submitted: 2, PerAgentDay: 1, NextOpenAt: 1789084800}, DayMax: 2,
		VerdictTTL: board.WorkStandingVerdictTTL, ResultsUntil: 1788912000, Tiers: []board.WorkStandingTier{{Name: "bug", Credits: 100, USDC: "0.20"}}}
	body := get("/work/" + id)
	if !strings.Contains(body, strings.Replace(panel, "%s", "false", 1)) || !strings.Contains(body, "Seats open today: 0 of 2 · next opening: 2026-09-11 00:00 UTC") {
		t.Error("a full standing task's page misses its unclaimable panel or the seats open today and the next opening (C585)")
	}
	// The directory has no panel: claims are made on the work's own page.
	if body := get("/work"); strings.Contains(body, `class="work-act"`) {
		t.Error("/work renders a Claim panel")
	}
}
