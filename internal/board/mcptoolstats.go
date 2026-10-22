package board

import (
	"context"
	"database/sql"
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
//	counters mcp_tool_code:YYYY-MM-DD:PROFILE:TOOL:CODE      failed calls by the refusal's error code
//	counters mcp_tool_skipped:YYYY-MM-DD                     the day's entries skipped for an invalid key
//
// PROFILE is one of MCPToolProfiles; TOOL a tool the profile registers
// whose name is ValidMCPToolName, anything else folded into MCPToolOther by
// the HTTP layer (and skipped here unless it has a tool name's shape); TOOL is MCPToolAny for the
// profile's callers of any tool. FAMILY is one of ClientFamilies. CODE is
// the failed call's error code (board.Error's Code, as the tool's structured
// refusal carries it) or MCPToolOther when it has none; at most
// MCPToolCodesMax codes are kept per profile, tool and day, any further code
// folded into MCPToolOther, so the table's size never depends on callers. No
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
	// MCPToolCodesMax is how many distinct error codes are kept per
	// profile, tool and day, MCPToolOther not counted; a further code is
	// counted under MCPToolOther.
	MCPToolCodesMax = 16

	mcpToolScopePrefix    = "mcp_tool:"
	mcpToolDistinctPrefix = "mcp_tool_distinct:"
	mcpToolSketchPrefix   = "mcp_tool_hll:"
	mcpToolSkippedPrefix  = "mcp_tool_skipped:"
	mcpToolCodePrefix     = "mcp_tool_code:"
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

// ValidMCPToolCode reports an error code a codes key can carry; the HTTP
// layer counts any other code as MCPToolOther.
func ValidMCPToolCode(code string) bool { return mcpToolNameRE.MatchString(code) }

// MCPToolCodeKey is the codes key of one profile, tool and error code.
func MCPToolCodeKey(profile, tool, code string) string {
	return profile + ":" + tool + ":" + code
}

func validMCPToolCodeKey(key string) bool {
	parts := strings.Split(key, ":")
	return len(parts) == 3 && validMCPToolPair(parts[0], parts[1]) && parts[1] != MCPToolAny && ValidMCPToolCode(parts[2])
}

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

// AddMCPToolStats adds one UTC day's tool call counts and error codes
// (MCPToolCodeKey) and merges its distinct-caller sketches, in one
// transaction: the HTTP layer's batched
// flush, never a request's path. Every key is checked, so no caller can
// put an identifier in a scope string; an entry with an invalid key (or a
// negative count, or no sketch) is skipped and counted under
// mcp_tool_skipped, so one bad key never loses the day's other counts.
func (s *Store) AddMCPToolStats(ctx context.Context, day string, counts, codes map[string]int64, sketches map[string]*ReaderSketch) error {
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
	if skipped, err = addMCPToolCodes(ctx, tx, day, codes, skipped); err != nil {
		return err
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

// addMCPToolCodes adds a day's error code counts in tx, keeping at most
// MCPToolCodesMax codes per profile and tool (the most frequent of the
// batch first, codes already stored kept), the rest under MCPToolOther. It
// returns skipped plus the entries it skipped for an invalid key.
func addMCPToolCodes(ctx context.Context, tx *sql.Tx, day string, codes map[string]int64, skipped int64) (int64, error) {
	keys := make([]string, 0, len(codes))
	for key, n := range codes {
		if !validMCPToolCodeKey(key) || n < 0 {
			skipped++
			continue
		}
		if n > 0 {
			keys = append(keys, key)
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		return codes[keys[i]] > codes[keys[j]] || codes[keys[i]] == codes[keys[j]] && keys[i] < keys[j]
	})
	held := map[string]int{} // PROFILE:TOOL -> distinct codes stored, MCPToolOther not counted
	for _, key := range keys {
		n := codes[key]
		cut := strings.LastIndexByte(key, ':')
		pair, code := key[:cut], key[cut+1:]
		if code != MCPToolOther {
			var exists int
			if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM counters WHERE scope=?", mcpToolCodePrefix+day+":"+key).Scan(&exists); err != nil {
				return skipped, err
			}
			if exists == 0 {
				stored, ok := held[pair]
				if !ok {
					prefix := mcpToolCodePrefix + day + ":" + pair + ":"
					if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM counters WHERE scope>=? AND scope<? AND scope<>?", prefix, prefix+"~", prefix+MCPToolOther).Scan(&stored); err != nil {
						return skipped, err
					}
				}
				if stored >= MCPToolCodesMax {
					held[pair] = stored
					key = pair + ":" + MCPToolOther
				} else {
					held[pair] = stored + 1
				}
			}
		}
		if err := addCounter(ctx, tx, mcpToolCodePrefix+day+":"+key, n); err != nil {
			return skipped, err
		}
	}
	return skipped, nil
}

// MCPToolCode is one error code's failed calls.
type MCPToolCode struct {
	Code   string `json:"code"`
	Errors int64  `json:"errors"`
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
	// ErrorCodes is the failed calls by error code, most first: the
	// refusal's code, MCPToolOther for one without a code or past
	// MCPToolCodesMax a day.
	ErrorCodes []MCPToolCode `json:"error_codes,omitempty"`
	codes      map[string]int64
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
			rows[k] = &MCPToolRow{Profile: profile, Tool: tool, Families: map[string]int64{}, codes: map[string]int64{}}
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
	if err := read(mcpToolCodePrefix, func(_, key string, n int64) {
		if validMCPToolCodeKey(key) {
			p := strings.Split(key, ":")
			row(p[0], p[1]).codes[p[2]] += n
		}
	}); err != nil {
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
		for c, n := range r.codes {
			p.codes[c] += n
		}
		r.ErrorCodes = mcpToolCodes(r.codes)
		w.Tools = append(w.Tools, *r)
	}
	for _, name := range MCPToolProfiles {
		if p := profiles[name]; p != nil {
			p.ErrorCodes = mcpToolCodes(p.codes)
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

// mcpToolCodes is codes most failed calls first, then by code.
func mcpToolCodes(codes map[string]int64) []MCPToolCode {
	out := make([]MCPToolCode, 0, len(codes))
	for c, n := range codes {
		out = append(out, MCPToolCode{Code: c, Errors: n})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Errors > out[j].Errors || out[i].Errors == out[j].Errors && out[i].Code < out[j].Code
	})
	if len(out) == 0 {
		return nil
	}
	return out
}
