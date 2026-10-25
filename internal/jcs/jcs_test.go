package jcs

import (
	"encoding/json"
	"testing"
)

func TestJCSRules(t *testing.T) {
	for _, c := range []struct {
		in   any
		want string
	}{
		// No HTML escaping, U+2028 literal, control characters short or \u00xx lowercase.
		{map[string]any{"s": "<a&b> \u2028 é \"q\" \\ \n\t\b\f\r \x01\x1f \x7f"}, "{\"s\":\"<a&b> \u2028 é \\\"q\\\" \\\\ \\n\\t\\b\\f\\r \\u0001\\u001f \x7f\"}"},
		// Keys in UTF-16 code-unit order: U+1F600 (D83D DE00) sorts before U+FFFF, unlike UTF-8 byte order.
		{map[string]any{"\uffff": 1, "\U0001F600": 2, "b": 3, "a": []any{nil, true, false, int64(-5)}}, "{\"a\":[null,true,false,-5],\"b\":3,\"\U0001F600\":2,\"\uffff\":1}"},
		{map[string]string{"q": "x"}, `{"q":"x"}`},
	} {
		got, err := Encode(c.in)
		if err != nil || string(got) != c.want {
			t.Errorf("Encode(%v) = %s %v, want %s", c.in, got, err, c.want)
		}
	}
	for _, bad := range []any{int64(1 << 53), "\xff", 1.5, map[string]any{"x": struct{}{}}} {
		if _, err := Encode(bad); err == nil {
			t.Errorf("Encode(%v) accepted", bad)
		}
	}
}

// Canonical re-encodes a JSON document: keys sorted, integers exact, no
// HTML escaping; a non-integer number or trailing data has no form here.
func TestCanonical(t *testing.T) {
	raw, err := json.Marshal(map[string]any{"b": []any{"<x>", 9007199254740991}, "a": map[string]string{"z": "1", "y": "2"}})
	if err != nil {
		t.Fatal(err)
	}
	got, err := Canonical(raw)
	if err != nil || string(got) != `{"a":{"y":"2","z":"1"},"b":["<x>",9007199254740991]}` {
		t.Fatalf("Canonical = %s %v", got, err)
	}
	for _, bad := range []string{`{"x":1.5}`, `{"x":1} {}`, `{"x":`} {
		if _, err := Canonical([]byte(bad)); err == nil {
			t.Errorf("Canonical(%s) accepted", bad)
		}
	}
}
