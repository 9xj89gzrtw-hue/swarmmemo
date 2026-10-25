package web

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

// C591: a record that carries its exact output bytes shows their encoding,
// size and a download link; /v/ID/output serves the bytes exactly, as a
// sandboxed attachment, never rendered. A hash-only record says so and has
// no output to serve.
func TestVerificationPageOutput(t *testing.T) {
	s := gateStore(t)
	out := []byte("Ran 3 tests\n\xcf\xf0\xe8\xe2\xe5\xf2 <script>alert(1)</script>\nOK\n") // cp1251, not UTF-8
	sum := sha256.Sum256(out)
	v := publishTestChecks(t, s, 6, []map[string]any{{"property": "tests", "state": "pass"}},
		map[string]any{"output_sha256": hex.EncodeToString(sum[:]), "output": base64.RawURLEncoding.EncodeToString(out), "stdio_encoding": "cp1251"})
	if v.OutputBytes != len(out) || v.OutputURL != "https://swarmmemo.com/v/"+v.ID+"/output" || v.StdioEncoding != "cp1251" {
		t.Fatalf("record output fields: %d %q %q", v.OutputBytes, v.OutputURL, v.StdioEncoding)
	}
	body := gateGet(s, "/v/"+v.ID).Body.String()
	for _, want := range []string{"<dt>Output encoding</dt><dd><code>cp1251</code>", `href="/v/` + v.ID + `/output" download`, "Download the exact output", fmt.Sprintf("(%d bytes,", len(out)),
		"cmp theirs.txt mine.txt", "# Its output was cp1251."} {
		if !strings.Contains(body, want) {
			t.Errorf("/v/ID misses %q", want)
		}
	}
	w := gateGet(s, "/v/"+v.ID+"/output")
	h := w.Header()
	if w.Code != 200 || !bytes.Equal(w.Body.Bytes(), out) {
		t.Fatalf("/v/ID/output: %d %q", w.Code, w.Body.Bytes())
	}
	if h.Get("Content-Type") != "application/octet-stream" || !strings.HasPrefix(h.Get("Content-Disposition"), "attachment;") || h.Get("X-Content-Type-Options") != "nosniff" ||
		!strings.Contains(h.Get("Content-Security-Policy"), "sandbox") || h.Get("ETag") != `"`+hex.EncodeToString(sum[:])+`"` {
		t.Errorf("/v/ID/output headers: %v", h)
	}
	plain := publishTestVerification(t, s, 7, false)
	if body := gateGet(s, "/v/"+plain.ID).Body.String(); !strings.Contains(body, "Hash only: the verifier did not publish the bytes.") || strings.Contains(body, "Download the exact output") {
		t.Error("/v/ID of a hash-only record shows a download")
	}
	if w := gateGet(s, "/v/"+plain.ID+"/output"); w.Code != 404 {
		t.Errorf("/v/ID/output of a hash-only record: %d", w.Code)
	}
	if w := gateGet(s, "/v/0000000000000000/output"); w.Code != 404 {
		t.Errorf("/v/ID/output of no record: %d", w.Code)
	}
}
