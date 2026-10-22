package services

import (
	"encoding/json"
	"testing"
)

// An integer parameter takes its digits quoted too, as a /call/ query field
// gives them; anything else quoted stays refused.
func TestPublicDataIntParamFromQueryString(t *testing.T) {
	spec := pdParam{Name: "limit", Kind: "int", Min: 1, Max: 100}
	for raw, want := range map[string]bool{`7`: true, `"7"`: true, `"100"`: true, `"101"`: false, `"0"`: false, `"7.5"`: false, `"1e2"`: false, `" 7"`: false, `""`: false, `"x"`: false} {
		if _, ok := spec.parse(json.RawMessage(raw)); ok != want {
			t.Errorf("parse(%s) = %v, want %v", raw, ok, want)
		}
	}
}
