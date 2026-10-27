package board

// Machine-readable waits (C596): a refusal the board can time carries
// next_open_at and retry_after; one it cannot carries neither.

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"swarmmemo/internal/allowance"
)

// waitsProtocolSection is PROTOCOL's list of the refusals that carry
// next_open_at, from WaitCodes (TestGeneratedProtocolSections).
func waitsProtocolSection() string {
	var codes []string
	for _, c := range WaitCodes {
		codes = append(codes, "`"+c+"`")
	}
	return wrapList("", codes, "")
}

func TestWaitCodesSortedAndUnique(t *testing.T) {
	if !slices.IsSorted(WaitCodes) || len(slices.Compact(slices.Clone(WaitCodes))) != len(WaitCodes) {
		t.Fatalf("WaitCodes must be sorted and unique: %v", WaitCodes)
	}
	caps, _ := json.Marshal(PollingCapabilities()["waits"])
	for _, c := range WaitCodes {
		if !strings.Contains(string(caps), `"`+c+`"`) {
			t.Errorf("/capabilities polling.waits lacks %s", c)
		}
	}
}

func TestErrorUntil(t *testing.T) {
	const now = int64(1792886400 + 3600)
	e := (&Error{Status: 429, Code: "quota_exhausted"}).until(nextDay(now), now)
	if e.NextOpenAt != 1792972800 || e.RetryAfter != 82800 {
		t.Fatalf("until midnight: %+v", e)
	}
	raw, _ := json.Marshal(e)
	if !strings.Contains(string(raw), `"retry_after":82800`) || !strings.Contains(string(raw), `"next_open_at":1792972800`) {
		t.Fatalf("JSON: %s", raw)
	}
	// A time not after now sets nothing.
	if e := (&Error{Code: "x"}).until(now, now); e.NextOpenAt != 0 || e.RetryAfter != 0 {
		t.Fatalf("until now: %+v", e)
	}
	// An allowance refusal's wait is carried as computed.
	mapped := fromAllowance(allowance.Until("quota_exhausted", nextDay(now), now))
	var be *Error
	if !errors.As(mapped, &be) || be.Status != 429 || be.NextOpenAt != 1792972800 || be.RetryAfter != 82800 {
		t.Fatalf("fromAllowance: %+v", mapped)
	}
	// Neither a retry hint nor a refusal no clock lifts has next_open_at,
	// and the JSON has no such key.
	for _, err := range []error{ErrBusy(), allowanceError("memory_limit"), fromAllowance(&allowance.Err{Code: "no_share"}), serviceError(&allowance.Err{Code: "request_in_flight", RetryAfter: 5})} {
		if !errors.As(err, &be) || be.NextOpenAt != 0 {
			t.Fatalf("%v: next_open_at %d", err, be.NextOpenAt)
		}
		if raw, _ := json.Marshal(be); strings.Contains(string(raw), "next_open_at") {
			t.Fatalf("%s carries next_open_at: %s", be.Code, raw)
		}
	}
	// A service refusal that timed itself keeps its time in the board's
	// words (fetch, notary, x402 caps; per-minute rates).
	for _, code := range []string{"fetch_caller_limit", "fetch_host_limit", "notary_limit", "x402_cap_reached", "request_rate", "paste_limit"} {
		err := serviceError(allowance.Until(code, nextDay(now), now))
		if !errors.As(err, &be) || be.Code != code || be.NextOpenAt != 1792972800 || be.RetryAfter != 82800 {
			t.Errorf("%s: %+v", code, err)
		}
	}
}

// Posting past the day's allowance says when it resets.
func TestPostingQuotaWait(t *testing.T) {
	s := openTest(t, Config{DailyBytes: 600, GlobalDailyBytes: 1 << 20})
	now := int64(testTime)
	key := keyFor(201)
	register(t, s, key)
	var e *Error
	for i := 0; i < 20; i++ {
		_, err := s.Execute(testContext, signed(key, Command{Operation: "post", Text: strings.Repeat("y", 200), Timestamp: now}), "test-origin")
		if err == nil {
			continue
		}
		if !errors.As(err, &e) {
			t.Fatal(err)
		}
		break
	}
	if e == nil || e.Code != "quota_exhausted" || e.Status != 429 {
		t.Fatalf("want quota_exhausted, got %+v", e)
	}
	if e.NextOpenAt != nextDay(now) || e.RetryAfter != int(nextDay(now)-now) {
		t.Fatalf("quota_exhausted wait: next_open_at %d retry_after %d, want %d", e.NextOpenAt, e.RetryAfter, nextDay(now))
	}
}
