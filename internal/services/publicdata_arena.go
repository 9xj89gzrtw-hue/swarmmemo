package services

import (
	"context"
	"errors"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// --- Arena (arena.ai, ex-LMArena) AI model leaderboard -----------------------
//
// Ported from Pythia's ai_leaderboard adapter (C563), whose row shape it keeps
// (rank, model, org, score, ci, votes). Pythia scraped arena.ai's page; this
// reads Arena's own published dataset, lmarena-ai/leaderboard-dataset on
// Hugging Face (CC BY 4.0), through the Hugging Face dataset viewer's filter
// endpoint: the board's latest split, one category, ordered by rank. A model
// or organization filter is a second query over the whole board, built only
// from the validated pattern below (no quote, % or _ can reach the clause).

const (
	arenaHost       = "datasets-server.huggingface.co"
	arenaDataset    = "lmarena-ai/leaderboard-dataset"
	arenaPage       = 100 // the viewer's page size; the most rows one query returns
	arenaTTL        = 6 * time.Hour
	arenaDefaultTop = 25
)

// arenaBoard is one leaderboard: the dataset subset and the category in it.
type arenaBoard struct{ Subset, Category, Label string }

// arenaBoards are the boards Pythia's adapter covered, plus vision and the
// text board without style control (some markets resolve on that tab). The
// text and vision boards are the style-controlled ones arena.ai shows by default.
var arenaBoards = map[string]arenaBoard{
	"text":          {"text_style_control", "overall", "Text Arena, overall (style control)"},
	"coding":        {"text_style_control", "coding", "Text Arena, coding category (style control)"},
	"webdev":        {"webdev", "overall", "WebDev (Code) Arena, overall"},
	"vision":        {"vision_style_control", "overall", "Vision Arena, overall (style control)"},
	"text_no_style": {"text", "overall", "Text Arena, overall (no style control)"},
}

var arenaBoardAliases = map[string]string{
	"overall-no-style-control": "text_no_style", "no_style_control": "text_no_style",
	"overall": "text", "chat": "text", "chatbot": "text", "lmarena": "text",
	"code": "webdev", "web": "webdev", "webdev-overall": "webdev", "programming": "coding",
}

var arenaTermRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 .()+:/-]{0,63}$`)

// arenaRow is one model, as Pythia's adapter returns it.
type arenaRow struct {
	Rank    *int64     `json:"rank"`
	Model   *string    `json:"model"`
	Org     *string    `json:"org"`
	License *string    `json:"license"`
	Score   *float64   `json:"score"`
	CI      []*float64 `json:"ci"`
	Votes   *int64     `json:"votes"`
}

// arenaPageDoc is one filter answer as cached.
type arenaPageDoc struct {
	Total int64      `json:"total"`
	Date  string     `json:"date"` // newest leaderboard_publish_date in the rows
	Rows  []arenaRow `json:"rows"`
}

func pyInt(v any) *int64 {
	f := pyFloat(v)
	if f == nil {
		return nil
	}
	n := int64(*f)
	return &n
}

// parseArena reads the dataset viewer's filter answer
// ({"rows":[{"row":{...}}],"num_rows_total":N}).
func parseArena(raw []byte) (any, error) {
	var body struct {
		Rows []struct {
			Row map[string]any `json:"row"`
		} `json:"rows"`
		Total any `json:"num_rows_total"`
	}
	if err := decodeJSON(raw, &body); err != nil {
		return nil, err
	}
	total := pyInt(body.Total)
	if total == nil || body.Rows == nil {
		return nil, errors.New("not a filter answer")
	}
	out := arenaPageDoc{Total: *total, Rows: []arenaRow{}}
	for _, r := range body.Rows {
		m := r.Row
		if m == nil {
			continue
		}
		row := arenaRow{Rank: pyInt(m["rank"]), Votes: pyInt(m["vote_count"])}
		if s := strings.TrimSpace(pyStr(m["model_name"])); s != "" {
			row.Model = sptr(s)
		}
		if s := strings.TrimSpace(pyStr(m["organization"])); s != "" {
			row.Org = sptr(s)
		}
		if s := strings.TrimSpace(pyStr(m["license"])); s != "" {
			row.License = sptr(s)
		}
		if f := pyFloat(m["rating"]); f != nil {
			row.Score = fptr(pyRound(*f, 1))
		}
		lo, hi := pyFloat(m["rating_lower"]), pyFloat(m["rating_upper"])
		if lo != nil && hi != nil {
			row.CI = []*float64{fptr(pyRound(*lo, 1)), fptr(pyRound(*hi, 1))}
		}
		if d := pyStr(m["leaderboard_publish_date"]); pdDateRE.MatchString(d) && d > out.Date {
			out.Date = d
		}
		out.Rows = append(out.Rows, row)
	}
	return out, nil
}

type arenaData struct {
	Board              string     `json:"board"`
	BoardLabel         string     `json:"board_label"`
	Subset             string     `json:"subset"`
	Category           string     `json:"category"`
	PublishDate        *string    `json:"leaderboard_publish_date"`
	Count              int        `json:"count"`
	MatchedEntries     int64      `json:"matched_entries"`
	TotalModelsOnBoard int64      `json:"total_models_on_board"`
	Models             []arenaRow `json:"models"`
	ScoreNote          string     `json:"score_note"`
	Note               string     `json:"note,omitempty"`
}

const arenaScoreNote = "score = Arena score (Bradley-Terry rating); ci = [low, high] confidence interval; overlapping intervals mean the rank order is statistically soft. votes = battles for this model."

func arenaBoardNorm(s string) (string, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	if a := arenaBoardAliases[s]; a != "" {
		s = a
	}
	return s, true
}

// arenaQuery is one filter request over a board's latest split.
func (r *pdRun) arenaQuery(ctx context.Context, b arenaBoard, model, org string) (arenaPageDoc, error) {
	where := `"category"='` + b.Category + `'`
	key := b.Subset + "|" + b.Category
	if model != "" {
		where += ` AND "model_name" ILIKE '%` + model + `%'`
		key += "|m:" + strings.ToLower(model)
	}
	if org != "" {
		where += ` AND "organization" ILIKE '%` + org + `%'`
		key += "|o:" + strings.ToLower(org)
	}
	q := url.Values{"dataset": {arenaDataset}, "config": {b.Subset}, "split": {"latest"}, "where": {where},
		"orderby": {`"rank"`}, "offset": {"0"}, "length": {strconv.Itoa(arenaPage)}}
	raw, err := r.fetch(ctx, pdFetch{Key: key, TTL: arenaTTL, Host: arenaHost, Path: "/filter", Query: q, MaxBytes: 1 << 20,
		Timeout: 30 * time.Second, Parse: parseArena})
	if err != nil {
		return arenaPageDoc{}, err
	}
	return unmarshalCached[arenaPageDoc](raw)
}

var dsArenaLeaderboard = &pdDataset{
	ID: "ai_model_leaderboard", SchemaVersion: 1,
	Title:       "AI model leaderboard (Arena)",
	Description: "Arena (arena.ai, ex-LMArena) leaderboard: models ranked by Arena score with confidence interval and vote count, from Arena's published dataset; optionally only models or organizations matching a name.",
	Output:      "data: board, board_label, subset, category, leaderboard_publish_date, count, matched_entries, total_models_on_board, models[] (by rank: rank, model, org, license, score, ci [low, high], votes), score_note",
	Params: []pdParam{
		{Name: "board", Kind: "enum", Enum: []string{"text", "coding", "webdev", "vision", "text_no_style"}, Norm: arenaBoardNorm, Default: "text",
			Doc: "text (overall), coding, webdev (Code Arena), vision, or text_no_style (overall without style control)"},
		{Name: "model", Kind: "string", MaxLen: 64, Pattern: arenaTermRE, Norm: pdTrim,
			Doc: "only models whose name contains this (case-insensitive), searched over the whole board"},
		{Name: "organization", Kind: "string", MaxLen: 64, Pattern: arenaTermRE, Norm: pdTrim,
			Doc: "only models whose organization contains this, e.g. anthropic, moonshot"},
		{Name: "limit", Kind: "int", Min: 1, Max: arenaPage, Default: strconv.Itoa(arenaDefaultTop), Doc: "most models returned, by rank"},
	},
	Validate: func(p *pdParams, _ time.Time) bool {
		if !p.Has("board") {
			p.Set("board", "text")
		}
		return true
	},
	Run: func(ctx context.Context, r *pdRun, p *pdParams) (any, error) {
		name := p.Str("board")
		b := arenaBoards[name]
		board, err := r.arenaQuery(ctx, b, "", "")
		if err != nil {
			return nil, err
		}
		out := arenaData{Board: name, BoardLabel: b.Label, Subset: b.Subset, Category: b.Category, MatchedEntries: board.Total,
			TotalModelsOnBoard: board.Total, ScoreNote: arenaScoreNote}
		rows := board.Rows
		model, org := p.Str("model"), p.Str("organization")
		date := board.Date
		if model != "" || org != "" {
			match, err := r.arenaQuery(ctx, b, model, org)
			if err != nil {
				return nil, err
			}
			rows, out.MatchedEntries = match.Rows, match.Total
			if match.Date > date {
				date = match.Date
			}
			if match.Total == 0 {
				out.Note = "no model on this board matches; a just-released model may not be rated yet, or Arena lists it under another name"
			}
		}
		limit := int(intOr(p, "limit", arenaDefaultTop))
		out.Models = rows[:min(limit, len(rows))]
		out.Count = len(out.Models)
		if date != "" {
			out.PublishDate = sptr(date)
			r.asOf = date
		}
		return out, nil
	},
	Source: "Arena (arena.ai), lmarena-ai/leaderboard-dataset via the Hugging Face dataset viewer", Hosts: []string{arenaHost},
	Licence: "CC BY 4.0", Attribution: "Arena leaderboard dataset (lmarena-ai/leaderboard-dataset, arena.ai), CC BY 4.0",
	TermsURL: "https://huggingface.co/datasets/lmarena-ai/leaderboard-dataset", TermsStatus: "CC BY 4.0 per the dataset card; attribution required",
	TTL: arenaTTL, Price: 1, Untrusted: true,
}
