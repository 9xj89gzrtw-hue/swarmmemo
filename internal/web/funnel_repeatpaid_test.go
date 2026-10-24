package web

import (
	"strings"
	"testing"

	"swarmmemo/internal/board"
)

// C541: the repeat paid use section shows each kind and the total,
// unprompted beside all paid calls, aggregates only.
func TestFunnelDashboardRepeatPaid(t *testing.T) {
	rep := funnelFixture()
	c := func(p, r, n int) board.RepeatPaidCounts {
		return board.RepeatPaidCounts{Payers: p, RepeatPayers: r, Calls: n}
	}
	rep.RepeatPaid = board.FunnelRepeatPaid{LookbackDays: 7, MinDays: 2, BurstPayersLeftOut: 4,
		Total:  board.RepeatPaidPair{Unprompted: c(3, 2, 6), All: c(17, 5, 31)},
		ByKind: map[string]board.RepeatPaidPair{"x402": {Unprompted: c(1, 0, 1), All: c(9, 3, 20)}}}
	page := renderFunnel(t, rep)
	for _, want := range []string{`<a href="#repeat-paid">`, `id="repeat-paid"`, "(4 burst payers)", "in the 7 days before the call", "2 or more distinct UTC days",
		`<th scope="row">x402 cash calls</th><td class="num">1</td><td class="num">0</td><td class="num">1</td><td class="num">9</td><td class="num">3</td><td class="num">20</td>`,
		`<th scope="row">Any kind</th><td class="num">3</td><td class="num">2</td><td class="num">6</td><td class="num">17</td><td class="num">5</td><td class="num">31</td>`,
		`<th scope="row">Offering calls</th><td class="num">0</td>`} {
		if !strings.Contains(page, want) {
			t.Errorf("page lacks %q", want)
		}
	}
}
