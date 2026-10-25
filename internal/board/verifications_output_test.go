package board

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

// withOutput sets output to out and output_sha256 to its hash.
func withOutput(out []byte) func(map[string]any) {
	return func(d map[string]any) {
		sum := sha256.Sum256(out)
		d["output_sha256"], d["output"] = hex.EncodeToString(sum[:]), base64.RawURLEncoding.EncodeToString(out)
	}
}

// C591: a record may carry the exact output bytes it hashed, signed in its
// data and checked against output_sha256, with the output's declared
// encoding; reads say where the bytes are and how many, and never inline
// them beyond the signed payload.
func TestVerificationOutputBytes(t *testing.T) {
	s := openTest(t, Config{})
	key := keyFor(46)
	out := []byte("Ran 3 tests in 0.001s\n\xcf\xf0\xe8\xe2\xe5\xf2\nOK\n") // cp1251 bytes are not UTF-8
	v := verificationOf(t, run(t, s, publishVerify(key, verifyRecord(func(d map[string]any) {
		withOutput(out)(d)
		d["stdio_encoding"] = "cp1251"
	}))))
	if !bytes.Equal(v.Output, out) || v.OutputBytes != len(out) || v.OutputURL != "https://"+s.config.ServiceID+VerificationPath+v.ID+VerificationOutputSuffix || v.StdioEncoding != "cp1251" {
		t.Fatalf("record %d %q %q", v.OutputBytes, v.OutputURL, v.StdioEncoding)
	}
	got := verificationOf(t, run(t, s, Command{Operation: "verify.get", Target: v.ID}))
	if !bytes.Equal(got.Output, out) || got.OutputURL != v.OutputURL {
		t.Fatalf("read back %q", got.Output)
	}
	// The bytes at the largest size publish; a hash-only record has none.
	max := bytes.Repeat([]byte{0xff}, VerificationOutputBytes)
	if v := verificationOf(t, run(t, s, publishVerify(key, verifyRecord(withOutput(max))))); v.OutputBytes != VerificationOutputBytes {
		t.Fatalf("largest output: %d bytes", v.OutputBytes)
	}
	if v := verificationOf(t, run(t, s, publishVerify(key, verifyRecord(nil)))); v.OutputBytes != 0 || v.OutputURL != "" || v.Output != nil {
		t.Fatalf("hash-only record has output %+v", v.OutputURL)
	}
	refused := func(name, want string, change func(map[string]any)) {
		t.Helper()
		_, err := s.Execute(testContext, publishVerify(key, verifyRecord(change)), "test-origin")
		var e *Error
		if !errorsAs(err, &e) || e.Code != "invalid_verification" || !strings.Contains(e.Message, want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	refused("mismatch", "output: its SHA-256 is", func(d map[string]any) {
		withOutput(out)(d)
		d["output_sha256"] = strings.Repeat("ab", 32)
	})
	refused("padded base64", "output: the exact output bytes, not canonical", func(d map[string]any) {
		withOutput([]byte("ok"))(d)
		d["output"] = base64.URLEncoding.EncodeToString([]byte("ok"))
	})
	refused("empty", "output: 1 to", func(d map[string]any) { d["output"] = "" })
	refused("over the cap", "leave it out to publish a larger output hash-only", withOutput(bytes.Repeat([]byte{'x'}, VerificationOutputBytes+1)))
	refused("far over the data cap", "leave it out to publish a larger output hash-only", withOutput(bytes.Repeat([]byte{'x'}, 37<<10)))
	refused("multi-line encoding", "stdio_encoding:", func(d map[string]any) { d["stdio_encoding"] = "utf-8\nlatin-1" })
	refused("long encoding", "stdio_encoding:", func(d map[string]any) { d["stdio_encoding"] = strings.Repeat("u", VerificationStdioEncodingMax+1) })
	if n := sqlCount(t, s, "SELECT count(*) FROM verifications"); n != 3 {
		t.Fatalf("%d records, want 3", n)
	}
}
