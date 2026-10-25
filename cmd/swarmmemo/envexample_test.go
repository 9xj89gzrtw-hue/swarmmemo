package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// envUndocumented is the reviewed debt list (C295-5): variables the Go code reads
// that .env.example does not name yet. It may only shrink. A new variable goes in
// .env.example (commented out with its default if it is optional), never here.
// Follow-up: one Go env table (name, default, doc) that generates .env.example.
var envUndocumented = []string{
	"ALLOWANCE_LEDGER", "ANON_PREFIX", "CONTENT_SCREEN", "CONTENT_URL",
	"CORROBORATE_URL", "DNS_ADDR", "DNS_NS", "DNS_WRITE", "DNS_ZONE", "EMAIL_DOMAIN",
	"EXPORT_ENDORSEMENTS", "FETCH_CONFIG", "FINGER_ADDR", "FOOTER_CREDIT_URL", "FUNNEL_PUBLIC",
	"GEMINI_ADDR", "GEMINI_CERT", "GEMINI_KEY", "GOPHER_ADDR", "GRAPH_DATASETS_FILE",
	"GRAPH_SUMMARY_DAILY_USD", "GRAPH_SUMMARY_MODEL", "GRAPH_SUMMARY_PRICES", "GRAPH_SUMMARY_UNTIL",
	"GRAPH_UNIVERSE_TTL", "HEAT_AUTHORS", "HEAT_TRUST", "HOST", "HOSTED_KEK_FILE", "INBOX_ENTRIES",
	"INDEXNOW_KEY", "INFERENCE_CONFIG", "JEV_KEY_FILE", "LOG_CHECKPOINT_INTERVAL", "LOG_KEY_FILE",
	"MODERATION", "MODERATION_POLICY_FILE", "MPP", "NAME_GATE", "NETWORK_RATE", "NOTARY_KEY_FILE",
	"NUDGES_OPENAI", "NUDGE_HOLDOUT", "OFFERINGS", "OFFERINGS_KEY_FILE", "OPENROUTER_API_KEY",
	"OPENROUTER_KEY_FILE", "OTS_CALENDARS", "OWN_NETWORKS", "PUBLIC_DATA_KEY_DIR", "RECEIVER_SCREEN",
	"RESERVED_HANDLES", "REVIEWS", "RUNS_CONFIG", "SERVICES", "SMTP_ADDR",
	"SMTP_ANONYMOUS", "SMTP_DOMAIN", "SWARMMEMO_NOSTR_KEY_FILE", "SWARMMEMO_NOSTR_PUBLISH",
	"SWARMMEMO_NOSTR_RELAYS", "SWARMMEMO_TEST_ALLOWANCE_LEDGER", "TCP_ADDR", "TOPUP_CONFIG", "TRUST",
	"VOTE_RECORDS", "WORK_REJECT_FEE", "WORK_USDC_RPC_URL",
	"X402_CONFIG",
}

// The getter forms the server uses: os.Getenv/LookupEnv, an injected getenv/env,
// and the typed readers in board.ParseFeatures.
var envReadRE = regexp.MustCompile(`(?:os\.Getenv|os\.LookupEnv|\bgetenv|\benv|\bboolean|\bnumber|\bvalue)\("([A-Z][A-Z0-9_]*[A-Z0-9])"`)

// TestEnvExampleNamesEveryVariableTheServerReads holds .env.example to the Go code
// both ways: no variable read but undocumented (outside the debt list), and no
// documented variable that nothing reads.
func TestEnvExampleNamesEveryVariableTheServerReads(t *testing.T) {
	read := map[string]string{}
	for _, top := range []string{"../../cmd", "../../internal"} {
		err := filepath.WalkDir(top, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return err
			}
			raw, err := os.ReadFile(path)
			for _, m := range envReadRE.FindAllStringSubmatch(string(raw), -1) {
				read[m[1]] = path
			}
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile("../../.env.example")
	if err != nil {
		t.Fatal(err)
	}
	documented := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?m)^#?\s*([A-Z][A-Z0-9_]+)=`).FindAllStringSubmatch(string(raw), -1) {
		documented[m[1]] = true
	}
	for name := range documented {
		if _, ok := read[name]; !ok {
			t.Errorf(".env.example names %s, which no Go code reads: remove it", name)
		}
	}
	for name, path := range read {
		if !documented[name] && !slices.Contains(envUndocumented, name) {
			t.Errorf("%s reads %s, which .env.example does not name: add it there (commented out with its default if optional)", path, name)
		}
	}
	for _, name := range envUndocumented {
		if documented[name] {
			t.Errorf("%s is now in .env.example: remove it from envUndocumented", name)
		} else if _, ok := read[name]; !ok {
			t.Errorf("%s is in envUndocumented but no Go code reads it: remove it from the list", name)
		}
	}
}
