package board

import (
	"context"
	"encoding/base64"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
)

// MCP tool calls, per UTC day (onboarding rebuild M): which hosted MCP tools
// are called, on which profile, by which client family, how often they
// fail, and by about how many distinct callers. Operator-only: read by
// `swarmmemo funnel mcp-tools` and the mcp_tools part of GET /admin/funnel,
// never by /stats or any public route.
//
// Like the reader and client counters they reuse counters(scope,value) and
// meta(key,value), so they need no schema change:
//
//	counters mcp_tool:YYYY-MM-DD:PROFILE:TOOL:FAMILY:METRIC  METRIC calls or errors
//	counters mcp_tool_distinct:YYYY-MM-DD:PROFILE:TOOL       the day's distinct-caller estimate
//	meta     mcp_tool_hll:YYYY-MM-DD:PROFILE:TOOL            the day's HyperLogLog sketch, kept MCPToolSketchDays
//	counters mcp_tool_skipped:YYYY-MM-DD                     the day's entries skipped for an invalid key
//
// PROFILE is one of MCPToolProfiles; TOOL a tool the profile registers
// whose name is ValidMCPToolName, anything else folded into MCPToolOther by
// the HTTP layer (and skipped here unless it has a tool name's shape); TOOL is MCPToolAny for the
// profile's callers of any tool. FAMILY is one of ClientFamilies. No
// address, token, key, User-Agent or argument is stored: the HTTP layer
// adds a daily-salted caller id (httpapi/mcp_toolstats.go) to the sketch,
// and only the sketch's registers reach storage. Its salt is memory only,
// so a day's callers cannot be linked to another day's: a window's
// "caller-days" is the sum of its days' distinct callers.

// MCPToolProfiles are the hosted MCP profiles counted: /mcp, /mcp/core and
// /mcp/assistant.
var MCPToolProfiles = []string{"mcp", "core", "assistant"}

// MCPToolMetrics are the per-family metrics stored.
var MCPToolMetrics = []string{"calls", "errors"}

const (
	// MCPToolOther is the bucket a tool name its profile does not register
	// is counted under, so cardinality stays the profile's tool set.
	MCPToolOther = "other"
	// MCPToolAny is the distinct-caller key for any tool of a profile.
	MCPToolAny = "any"
	// MCPToolSketchDays is how many days' sketches are kept: a closed day's
	// estimate is final, so only today's and yesterday's are needed.
	MCPToolSketchDays = 2

	mcpToolScopePrefix    = "mcp_tool:"
	mcpToolDistinctPrefix = "mcp_tool_distinct:"
	mcpToolSketchPrefix   = "mcp_tool_hll:"
	mcpToolSkippedPrefix  = "mcp_tool_skipped:"
)

var mcpToolNameRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,47}$`)

// ValidMCPToolName reports a tool name a counts key can carry; the HTTP
// layer counts any other registered name as MCPToolOther.
func ValidMCPToolName(name string) bool { return mcpToolNameRE.MatchString(name) }

// MCPToolKey is the counts key of one profile, tool, family and metric.
func MCPToolKey(profile, tool, family, metric string) string {
	return profile + ":" + tool + ":" + family + ":" + metric
}

// MCPToolDistinctKey is the sketch key of one profile and tool.
func MCPToolDistinctKey(profile, tool string) string { return profile + ":" + tool }

func validMCPToolPair(profile, tool string) bool {
	return slices.Contains(MCPToolProfiles, profile) && mcpToolNameRE.MatchString(tool)
}

func validMCPToolKey(key string) bool {
	parts := strings.Split(key, ":")
	return len(parts) == 4 && validMCPToolPair(parts[0], parts[1]) && validClientFamily(parts[2]) && slices.Contains(MCPToolMetrics, parts[3])
}

func validMCPToolDistinctKey(key string) bool {
	profile, tool, ok := strings.Cut(key, ":")
	return ok && validMCPToolPair(profile, tool)
}

// AddMCPToolStats adds one UTC day's tool call counts and merges its
// distinct-caller sketches, in one transaction: the HTTP layer's batched
// flush, never a request's path. Every key is checked, so no caller can
// put an identifier in a scope string; an entry with an invalid key (or a
// negative count, or no sketch) is skipped and counted under
// mcp_tool_skipped, so one bad key never loses the day's other counts.
func (s *Store) AddMCPToolStats(ctx context.Context, day string, counts map[string]int64, sketches map[string]*ReaderSketch) error {
	if !validReaderDay(day) {
		return fmt.Errorf("mcp tool stats: invalid day")
	}
	var skipped int64
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for key, n := range counts {
		if !validMCPToolKey(key) || n < 0 {
			skipped++
			continue
		}
		if n == 0 {
			continue
		}
		if err = addCounter(ctx, tx, mcpToolScopePrefix+day+":"+key, n); err != nil {
			return err
		}
	}
	for key, h := range sketches {
		if !validMCPToolDistinctKey(key) || h == nil {
			skipped++
			continue
		}
		merged := *h
		stored, err := readSketch(ctx, tx, mcpToolSketchPrefix+day+":"+key)
		if err != nil {
			return err
		}
		if stored != nil {
			merged.Merge(stored)
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
			mcpToolSketchPrefix+day+":"+key, base64.StdEncoding.EncodeToString(merged.MarshalBinary())); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO counters(scope,value) VALUES(?,?) ON CONFLICT(scope) DO UPDATE SET value=excluded.value",
			mcpToolDistinctPrefix+day+":"+key, merged.Estimate()); err != nil {
			return err
		}
	}
	if skipped > 0 {
		if err = addCounter(ctx, tx, mcpToolSkippedPrefix+day, skipped); err != nil {
			return err
		}
	}
	cutoff := s.now().UTC().Truncate(24*time.Hour).AddDate(0, 0, -(MCPToolSketchDays - 1)).Format("2006-01-02")
	if _, err = tx.ExecContext(ctx, "DELETE FROM meta WHERE key>=? AND key<?", mcpToolSketchPrefix, mcpToolSketchPrefix+cutoff); err != nil {
		return err
	}
	return tx.Commit()
}

// MCPToolRow is one profile's tool over a window.
type MCPToolRow struct {
	Profile string `json:"profile"`
	Tool    string `json:"tool"`
	Calls   int64  `json:"calls"`
	Errors  int64  `json:"errors"`
	// CallerDays is the sum of the window's daily distinct callers
	// (HyperLogLog estimates, ReaderSketchError): callers are not linkable
	// across days.
	CallerDays int64 `json:"caller_days"`
	// Families is calls by client family.
	Families map[string]int64 `json:"families"`
}

// MCPToolWindow is the tool calls of the days From to To (UTC, inclusive).
type MCPToolWindow struct {
	Days int    `json:"days"`
	From string `json:"from"`
	To   string `json:"to"`
	// Profiles is each profile's callers of any tool (caller-days) and calls.
	Profiles []MCPToolRow `json:"profiles"`
	// Tools is every profile's tools called in the window, most calls first.
	Tools []MCPToolRow `json:"tools"`
	// Skipped is the entries the window's flushes skipped for an invalid
	// key: a bug in the HTTP layer's key building, never a caller's input.
	Skipped int64 `json:"skipped,omitempty"`
}

// MCPToolWindows are the windows the operator reads: the last 7 and 30 days.
var MCPToolWindows = []int{7, 30}

// MCPToolReport is the tool calls of each of MCPToolWindows ending end's
// UTC day.
func (s *Store) MCPToolReport(ctx context.Context, end time.Time) ([]MCPToolWindow, error) {
	var out []MCPToolWindow
	for _, days := range MCPToolWindows {
		w, err := s.MCPToolStats(ctx, end, days)
		if err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, nil
}

// MCPToolStats is the tool calls of the days UTC days ending with end's.
func (s *Store) MCPToolStats(ctx context.Context, end time.Time, days int) (MCPToolWindow, error) {
	if days < 1 || days > ActivityDays {
		return MCPToolWindow{}, fmt.Errorf("mcp tool stats: days is 1 to %d", ActivityDays)
	}
	last := end.UTC().Truncate(24 * time.Hour)
	w := MCPToolWindow{Days: days, From: last.AddDate(0, 0, -(days - 1)).Format("2006-01-02"), To: last.Format("2006-01-02")}
	rows := map[string]*MCPToolRow{}
	row := func(profile, tool string) *MCPToolRow {
		k := profile + ":" + tool
		if rows[k] == nil {
			rows[k] = &MCPToolRow{Profile: profile, Tool: tool, Families: map[string]int64{}}
		}
		return rows[k]
	}
	read := func(prefix string, each func(day, key string, value int64)) error {
		q, err := s.db.QueryContext(ctx, "SELECT scope,value FROM counters WHERE scope>=? AND scope<?", prefix+w.From, prefix+w.To+";")
		if err != nil {
			return err
		}
		defer q.Close()
		for q.Next() {
			var scope string
			var value int64
			if err = q.Scan(&scope, &value); err != nil {
				return err
			}
			day, key, ok := strings.Cut(strings.TrimPrefix(scope, prefix), ":")
			if ok && day >= w.From && day <= w.To {
				each(day, key, value)
			}
		}
		return q.Err()
	}
	if err := read(mcpToolScopePrefix, func(_, key string, n int64) {
		if !validMCPToolKey(key) {
			return
		}
		p := strings.Split(key, ":")
		r := row(p[0], p[1])
		switch p[3] {
		case "calls":
			r.Calls += n
			r.Families[p[2]] += n
		case "errors":
			r.Errors += n
		}
	}); err != nil {
		return w, err
	}
	if err := s.db.QueryRowContext(ctx, "SELECT coalesce(sum(value),0) FROM counters WHERE scope>=? AND scope<=?", mcpToolSkippedPrefix+w.From, mcpToolSkippedPrefix+w.To).Scan(&w.Skipped); err != nil {
		return w, err
	}
	if err := read(mcpToolDistinctPrefix, func(_, key string, n int64) {
		if validMCPToolDistinctKey(key) {
			profile, tool, _ := strings.Cut(key, ":")
			row(profile, tool).CallerDays += n
		}
	}); err != nil {
		return w, err
	}
	profiles := map[string]*MCPToolRow{}
	for _, r := range rows {
		if r.Tool == MCPToolAny {
			profiles[r.Profile] = r
		}
	}
	for _, r := range rows {
		if r.Tool == MCPToolAny {
			continue
		}
		p := profiles[r.Profile]
		if p == nil {
			p = row(r.Profile, MCPToolAny)
			profiles[r.Profile] = p
		}
		p.Calls += r.Calls
		p.Errors += r.Errors
		for f, n := range r.Families {
			p.Families[f] += n
		}
		w.Tools = append(w.Tools, *r)
	}
	for _, name := range MCPToolProfiles {
		if p := profiles[name]; p != nil {
			w.Profiles = append(w.Profiles, *p)
		}
	}
	sort.Slice(w.Tools, func(i, j int) bool {
		a, b := w.Tools[i], w.Tools[j]
		if a.Calls != b.Calls {
			return a.Calls > b.Calls
		}
		if a.Profile != b.Profile {
			return a.Profile < b.Profile
		}
		return a.Tool < b.Tool
	})
	return w, nil
}
