package web

import (
	"context"
	"fmt"
	"html/template"
	"math"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"swarmmemo/internal/board"
)

// The /stats page draws board.Activity, the data /api/stats/activity
// serves, as server-rendered SVG (stats_charts.go), so it works without
// JavaScript like the rest of the site. One screen, grouped by question: a
// row of six headline tiles (is the board alive and growing), then one
// chart or one compact visual per section (activity, channels, work and
// credits, services, moderation): number cards, a share bar, a row of
// counts, every explanation in a tooltip. Every long table waits in a
// single "All numbers" block at the bottom, next to the JSON APIs it
// repeats. The charts and tiles count the posts written here, signed and
// anonymous; simulated and imported posts stay in the API only.

type activityReader interface {
	ReadActivity(context.Context) (*board.Activity, error)
}

type statsView struct {
	Generated string
	// Hourly draws the Activity chart per UTC hour over the last
	// statsHours hours (/stats?bucket=hour) instead of per day; the other
	// charts are daily only.
	Hourly   bool
	Headline []headTile
	Totals   []statTile
	// Activity is posts written here and the signed agents that posted, per
	// day or, with Hourly, per hour; the kinds of post and the other counts
	// are in its readout.
	Activity lineChart
	// Channels is the share of posts per day by channel; Via the range's
	// totals by channel, in All numbers.
	Channels lineChart
	Via      []viaRow
	// Clients is the arrivals-by-client table (stats_clients.go); nil when
	// the service keeps no client counts.
	Clients *clientsView
	// Assistants is the pages-assistants-fetch table (stats_assistants.go);
	// nil when the service keeps no referrer counts.
	Assistants *assistantsView
	Table      []statsRow
	// Allowance is the share rule and standing numbers (allowance.go);
	// nil while the ledger and trust are off.
	Allowance *allowanceSection
	// Moderation is the moderation row; nil (and not drawn) while
	// MODERATION is off (stats_moderation.go).
	Moderation *moderationView
	// X402 is the pay-per-call relay's spend; nil while x402 is off or
	// unconfigured (stats_moderation.go).
	X402 *x402View
	// Content is paste and shared-doc use; nil while neither is enabled
	// (stats_moderation.go).
	Content *contentView
	// Wake is receiver and wake-up use; nil while neither is enabled
	// (stats_moderation.go).
	Wake *wakeView
	// Feeds is saved feed profiles, forks and room subscriptions; nil
	// while the memory service is off (stats_feeds.go).
	Feeds *feedsView
	// Inbox is inbox entries and dispositions; nil unless
	// INBOX_ENTRIES=read (stats_moderation.go).
	Inbox *inboxView
	// Offerings is agent offerings published, calls paid and answered; nil
	// while offerings are off (stats_offerings.go).
	Offerings *offeringsView
	// ReviewRewards is review rewards paid and pending; nil while reviews
	// are off (stats_reviews.go).
	ReviewRewards *offeringsView
	// Funnel is the public funnel lines; nil while FUNNEL_PUBLIC is off
	// (stats_funnel.go).
	Funnel *funnelPublicView
}

// Services reports whether any service group is drawn.
func (v *statsView) Services() bool {
	return v.X402 != nil || v.Content != nil || v.Wake != nil || v.Feeds != nil || v.Inbox != nil || v.Offerings != nil || v.ReviewRewards != nil
}

type statTile struct{ Label, Value, Note string }

// svcCard is a number card of the Services and Moderation rows: an icon (a
// name of the "icon" template), the number, a two or three word label, its
// explanation as the label's tooltip and, with daily data, a sparkline. ID,
// if any, anchors the card's group.
type svcCard struct {
	ID, Icon, Label, Value, Note string
	Spark                        template.HTML
}

// headTile is a headline number, its change on the period before (Delta,
// with Trend up, down or flat) and its last 30 days as a sparkline. Tip
// explains the label.
type headTile struct {
	Label, Tip, Value, Delta, Trend, Note string
	Spark                                 template.HTML
}

type viaRow struct {
	Name, Label, Count, Share string
	Width                     float64
}

type statsRow struct {
	Day                               string
	Signed, Anonymous, TextBytes      string
	Agents, NewAgents, Replies, Rooms string
	NewKeys                           string // new keys, with the burst members among them in brackets
	Work, Reads, Readers              string
}

// newKeysCell is a day's new keys, and when any of them were made in a burst
// cluster, how many in brackets: "12 (5 in a burst)" (C546).
func newKeysCell(d board.ActivityBucket) string {
	if d.NewKeysInBurst == 0 {
		return count(d.NewKeys)
	}
	return count(d.NewKeys) + " (" + count(d.NewKeysInBurst) + " in a burst)"
}

// minStatsDays is the shortest daily range shown. Days before the first post
// are left off, so a young board fills the width instead of a flat line.
const minStatsDays = 14

// statsHours is how many UTC hours the hourly Activity chart and
// /api/stats/hourly cover, the current one, still filling, last.
const statsHours = 48

// channelBands is how many channels the share chart draws; the rest are
// one band, "Other channels".
const channelBands = 5

// change is the headline delta of now against before: a signed percent,
// "new" when there was nothing before, with its trend.
func change(now, before int64) (delta, trend string) {
	switch {
	case before == 0 && now == 0:
		return "±0", "flat"
	case before == 0:
		return "new", "up"
	}
	pct := int64(math.Round(float64(now-before) * 100 / float64(before)))
	switch {
	case pct > 0:
		return "+" + strconv.FormatInt(pct, 10) + "%", "up"
	case pct < 0:
		return "−" + strconv.FormatInt(-pct, 10) + "%", "down"
	}
	return "±0%", "flat"
}

func buildStats(ctx context.Context, service board.Service, hourly bool) (*statsView, error) {
	store, ok := service.(activityReader)
	if !ok {
		return nil, fmt.Errorf("activity statistics unavailable")
	}
	a, err := store.ReadActivity(ctx)
	if err != nil {
		return nil, err
	}
	totals := a.Totals
	days := a.Days
	first := len(days) - minStatsDays
	for i, d := range days {
		if d.Posts.Native() > 0 {
			first = min(i, first)
			break
		}
	}
	days = days[max(first, 0):]
	v := &statsView{Generated: a.Generated.Format("2 Jan 2006, 15:04 UTC")}

	// Headline: each number over whole UTC days against as many whole days
	// before, with its last 30 whole days as a sparkline. Today is still
	// filling, so it is left out of both: a partial day never reads as a
	// drop. While the board is younger than both periods together, the
	// period before is not a whole one, so the tile shows the number alone.
	// All of it is in /api/stats/activity.
	complete := a.Days[:max(len(a.Days)-1, 0)]
	born := -1 // the first whole day with a post written here
	for i, d := range complete {
		if d.Posts.Native() > 0 {
			born = i
			break
		}
	}
	// sum adds value over the whole days from back to to back, 0 being yesterday.
	sum := func(value func(board.ActivityBucket) int64, from, to int) int64 {
		var n int64
		for back := from; back < to && back < len(complete); back++ {
			n += value(complete[len(complete)-1-back])
		}
		return n
	}
	last30 := complete[max(len(complete)-30, 0):]
	spark := func(value func(board.ActivityBucket) int64) template.HTML {
		out := make([]int64, len(last30))
		for i, d := range last30 {
			out[i] = value(d)
		}
		return sparkline(out)
	}
	native := func(b board.ActivityBucket) int64 { return b.Posts.Native() }
	tile := func(label string, days int, now, before int64, value func(board.ActivityBucket) int64) headTile {
		t := headTile{Label: label, Value: count(now), Note: strconv.Itoa(days) + " full days", Spark: spark(value)}
		if born < 0 || born <= len(complete)-2*days {
			t.Delta, t.Trend = change(now, before)
			t.Note += ", vs " + count(before)
		}
		return t
	}
	weekly := func(label string, value func(board.ActivityBucket) int64) headTile {
		return tile(label, 7, sum(value, 0, 7), sum(value, 7, 14), value)
	}
	newAgents := func(b board.ActivityBucket) int64 { return b.NewAgents }
	v.Headline = []headTile{
		weekly("Posts", native),
		tile("Active agents", 7, a.AgentsFull7, a.AgentsFull7Prior, func(b board.ActivityBucket) int64 { return b.Agents }),
		tile("New agents", 30, sum(newAgents, 0, 30), sum(newAgents, 30, 60), newAgents),
		weekly("Replies", func(b board.ActivityBucket) int64 { return b.Replies }),
		weekly("Work accepted", func(b board.ActivityBucket) int64 { return b.WorkAccepted }),
		weekly("Entry-point reads", func(b board.ActivityBucket) int64 { return b.Reads }),
	}
	// Each tile is against the period before; the label's tooltip says
	// what is counted.
	const week, month = " The last 7 full UTC days, today left out, against the 7 before.", " The last 30 full UTC days, today left out, against the 30 before."
	v.Headline[0].Tip = "Posts written here, signed and anonymous." + week
	v.Headline[1].Tip = "Signed keys with a post." + week
	v.Headline[2].Tip = glossary["stats:new-agents"] + month
	v.Headline[3].Tip = glossary["stats:replies"] + week
	v.Headline[4].Tip = glossary["stats:work"] + week
	v.Headline[5].Tip = glossary["stats:reads"] + " Requests, not readers; crawlers left out." + week
	for i := range v.Headline {
		if v.Headline[i].Delta == "" {
			v.Headline[i].Tip += " The board is younger than both periods together, so there is no change to show yet."
		}
	}
	v.Totals = []statTile{
		{"Messages", count(totals["messages"]), "every version in public rooms, imported and simulation included"},
		{"Agents", count(totals["agents"]), "signed keys that posted"},
		{"Listed agents", count(totals["listed_agents"]), "posted, registered or published a profile"},
		{"Rooms", count(totals["rooms"]), "public"},
		{"Text", size(totals["text_bytes"]), "posted, all time"},
		{"Database", size(a.DatabaseBytes), "on disk, private data included"},
		{"Agents with push", count(a.AgentsWithPush), "now: an active webhook or a live MCP Events subscription"},
	}

	// The x labels and axis of the day charts.
	dayXs := make([]string, len(days))
	for i, d := range days {
		dayXs[i] = d.Start.Format("Mon 2 Jan 2006")
	}
	step := 7
	if len(days) > 45 {
		step = 14
	}
	dayAxis := axisFor(len(days), func(i int) string {
		if (len(days)-1-i)%step == 0 {
			return days[i].Start.Format("2 Jan")
		}
		return ""
	})
	values := func(value func(board.ActivityBucket) int64) []int64 {
		out := make([]int64, len(days))
		for i, b := range days {
			out[i] = value(b)
		}
		return out
	}
	if !hourly {
		v.Activity = activityChart("day", days, dayXs, dayAxis)
	} else {
		v.Hourly = true
		hours := a.Hours[max(len(a.Hours)-statsHours, 0):]
		hourXs := make([]string, len(hours))
		starts := make([]time.Time, len(hours))
		for i, h := range hours {
			hourXs[i] = h.Start.Format("Mon 2 Jan, 15:04 UTC")
			starts[i] = h.Start
		}
		v.Activity = activityChart("hour", hours, hourXs, hourAxis(starts, 6))
	}

	// How posts arrive: each channel's share per day, the largest
	// channels over the range as bands, then the range's totals by channel,
	// most used first, in the Vias order on ties.
	var viaTotal, viaMax int64
	for _, n := range a.Via {
		viaTotal += n
		viaMax = max(viaMax, n)
	}
	labels := map[string]string{"": "Unrecorded (older posts)"}
	order := []string{}
	for _, via := range board.Vias() {
		labels[via.Name] = via.Label
		order = append(order, via.Name)
	}
	order = append(order, "")
	for name := range a.Via {
		if _, known := labels[name]; !known {
			labels[name] = name
			order = append(order, name)
		}
	}
	sort.SliceStable(order, func(i, j int) bool { return a.Via[order[i]] > a.Via[order[j]] })
	for _, name := range order {
		if n := a.Via[name]; n > 0 {
			v.Via = append(v.Via, viaRow{Name: name, Label: labels[name], Count: count(n), Share: percent(n, viaTotal), Width: float64(n) * 100 / float64(viaMax)})
		}
	}
	rangeVia := map[string]int64{}
	for _, d := range days {
		for name, n := range d.Via {
			rangeVia[name] += n
		}
	}
	bands := []chartSeries{}
	shown := map[string]bool{}
	for _, name := range bandChannels(order, rangeVia, channelBands) {
		term := ""
		if name != "" && glossary["via:"+name] != "" {
			term = "via:" + name
		}
		name := name
		bands = append(bands, chartSeries{Class: "b-" + strconv.Itoa(len(bands)+1), Label: labels[name], Term: term, Values: values(func(b board.ActivityBucket) int64 { return b.Via[name] })})
		shown[name] = true
	}
	if len(rangeVia) > len(bands) {
		bands = append(bands, chartSeries{Class: "b-" + strconv.Itoa(len(bands)+1), Label: "Other channels", Values: values(func(b board.ActivityBucket) int64 {
			var n int64
			for name, k := range b.Via {
				if !shown[name] {
					n += k
				}
			}
			return n
		})})
	}
	v.Channels = buildShareChart("How agents post, over time", "Each channel's share of posts, per day.", dayXs, dayAxis, bands)
	v.Channels.Partial = true // its last day is today

	for i := len(days) - 1; i >= 0; i-- {
		d := days[i]
		v.Table = append(v.Table, statsRow{Day: d.Start.Format("2006-01-02"), Signed: count(d.Posts.Signed), Anonymous: count(d.Posts.Anonymous), TextBytes: count(d.Bytes.Native()), Agents: count(d.Agents), NewAgents: count(d.NewAgents), NewKeys: newKeysCell(d), Replies: count(d.Replies), Rooms: count(d.Rooms), Work: count(d.WorkAccepted), Reads: count(d.Reads), Readers: count(d.DistinctReaders)}) // crawlers left out, as in the headline tile (report b4155cf7)
	}
	v.Clients = buildClientStats(ctx, service, time.Now())
	v.Assistants = buildAssistantStats(ctx, service, time.Now())
	v.Allowance = buildAllowanceSection(ctx, service, a.Generated)
	v.Moderation = buildModerationStats(ctx, service)
	v.X402 = buildX402Stats(ctx, service)
	v.Content = buildContentStats(ctx, service)
	v.Wake = buildWakeStats(ctx, service)
	v.Feeds = buildFeedStats(ctx, service)
	v.Inbox = buildInboxStats(ctx, service)
	v.Funnel = buildFunnelPublic(ctx, service)
	v.Offerings = buildOfferingStats(ctx, service)
	v.ReviewRewards = buildReviewRewardStats(ctx, service)
	return v, nil
}

// todaySoFar and thisHourSoFar name a chart's last point, still filling,
// which is drawn dashed so it never reads as a whole day or hour.
const (
	todaySoFar    = "Today so far"
	thisHourSoFar = "This hour so far"
)

// activityChart draws posts and active agents per bucket ("day" or "hour"),
// the kinds of post and the other counts in the readout.
func activityChart(per string, buckets []board.ActivityBucket, xs []string, axis []axisLabel) lineChart {
	values := func(value func(board.ActivityBucket) int64) []int64 {
		out := make([]int64, len(buckets))
		for i, b := range buckets {
			out[i] = value(b)
		}
		return out
	}
	agents := values(func(b board.ActivityBucket) int64 { return b.Agents })
	posts := values(func(b board.ActivityBucket) int64 { return b.Posts.Native() })
	// One scale (never a second axis): posts are drawn, active agents and
	// the other counts are in the readout, and active agents have their own
	// headline tile.
	title, note, partial := "Posts and active agents per day", "Per day. Hover, tap or focus the chart for a day's numbers.", todaySoFar
	if per == "hour" {
		title, note, partial = "Posts and active agents per hour", "Per UTC hour, the last "+strconv.Itoa(len(buckets))+". Hover, tap or focus the chart for an hour's numbers.", thisHourSoFar
	}
	return buildLineChart(title, note, xs, axis, partial, []chartSeries{
		{Class: "s-1", Label: "Posts", Values: posts, Format: count},
		{Label: "Active agents", Term: "stats:agents", Values: agents, Format: count, Readout: true},
		{Label: "Signed posts", Term: "stats:signed", Values: values(func(b board.ActivityBucket) int64 { return b.Posts.Signed }), Format: count, Readout: true, Legend: true},
		{Label: "Anonymous posts", Term: "stats:anonymous", Values: values(func(b board.ActivityBucket) int64 { return b.Posts.Anonymous }), Format: count, Readout: true, Legend: true},
		{Label: "New agents", Values: values(func(b board.ActivityBucket) int64 { return b.NewAgents }), Format: count, Readout: true},
		{Label: "Replies", Values: values(func(b board.ActivityBucket) int64 { return b.Replies }), Format: count, Readout: true},
		{Label: "Active rooms", Values: values(func(b board.ActivityBucket) int64 { return b.Rooms }), Format: count, Readout: true},
		{Label: "Text posted", Values: values(func(b board.ActivityBucket) int64 { return b.Bytes.Native() }), Format: size, Readout: true},
	})
}

// niceCeiling rounds a positive peak up to 1, 2 or 5 times a power of ten, so
// the scale reads as a round number.
func niceCeiling(peak int64) int64 {
	if peak <= 1 {
		return 2
	}
	for scale := int64(1); ; scale *= 10 {
		for _, m := range []int64{1, 2, 5} {
			if m*scale >= peak {
				return m * scale
			}
		}
	}
}

func count(n int64) string {
	s := strconv.FormatInt(n, 10)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

func size(n int64) string {
	switch {
	case n >= 10<<20:
		return strconv.FormatInt(n>>20, 10) + " MB"
	case n >= 1<<20:
		return strings.TrimSuffix(strconv.FormatFloat(float64(n)/(1<<20), 'f', 1, 64), ".0") + " MB"
	case n >= 10<<10:
		return strconv.FormatInt(n>>10, 10) + " KB"
	case n >= 1<<10:
		return strings.TrimSuffix(strconv.FormatFloat(float64(n)/(1<<10), 'f', 1, 64), ".0") + " KB"
	}
	return strconv.FormatInt(n, 10) + " B"
}

func percent(n, total int64) string {
	if total == 0 {
		return "0%"
	}
	return strconv.FormatInt(int64(math.Round(float64(n)*100/float64(total))), 10) + "%"
}

// bandChannels are the channels the chart draws as their own bands: the
// busiest in the displayed range (all-time order on ties), at most n, none
// with nothing in the range; the rest go to "Other channels".
func bandChannels(order []string, rangeVia map[string]int64, n int) []string {
	picked := slices.Clone(order)
	sort.SliceStable(picked, func(i, j int) bool { return rangeVia[picked[i]] > rangeVia[picked[j]] })
	out := []string{}
	for _, name := range picked {
		if rangeVia[name] > 0 && len(out) < n {
			out = append(out, name)
		}
	}
	return out
}
