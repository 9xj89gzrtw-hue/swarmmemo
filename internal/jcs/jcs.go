// Package jcs is JCS (RFC 8785), the JSON Canonicalization Scheme, for the
// JSON values SwarmMemo signs or MACs: objects with string keys, arrays,
// strings, integers, booleans and null. MPP's request and opaque parameters
// are JCS before base64url (the challenge id is an HMAC over their encoded
// form); the A2A agent card's signatures cover the card's JCS form.
// encoding/json is not JCS: it escapes <, >, & and U+2028/U+2029, and
// orders keys by bytes rather than UTF-16 code units. Non-integer numbers
// are refused rather than given ECMAScript's float formatting.
package jcs

import (
	"bytes"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

var errJCS = errors.New("jcs: value has no JCS form here")

// DepthMax bounds nesting (pay.JSONDepthMax is the same value).
const DepthMax = 16

// maxSafeInteger is 2^53-1: JCS numbers are IEEE 754 doubles, so a larger
// integer would not survive a round trip.
const maxSafeInteger = 1<<53 - 1

// Encode is v in JCS form. It takes map[string]any, map[string]string,
// []any, []string, string, int, int64, json.Number (an integer), bool and nil.
func Encode(v any) ([]byte, error) {
	var b bytes.Buffer
	if err := jcsValue(&b, v, 0); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// Canonical is the JCS form of one JSON document, such as a marshalled
// struct or map: decoded with numbers kept exact, then encoded by Encode.
func Canonical(raw []byte) ([]byte, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		return nil, err
	}
	if d.More() {
		return nil, errJCS
	}
	return Encode(v)
}

func jcsValue(b *bytes.Buffer, v any, depth int) error {
	if depth > DepthMax {
		return errJCS
	}
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		b.WriteString(strconv.FormatBool(x))
	case string:
		return jcsString(b, x)
	case int:
		return jcsValue(b, int64(x), depth)
	case int64:
		if x > maxSafeInteger || x < -maxSafeInteger {
			return errJCS
		}
		b.WriteString(strconv.FormatInt(x, 10))
	case json.Number:
		n, err := strconv.ParseInt(string(x), 10, 64)
		if err != nil {
			return errJCS
		}
		return jcsValue(b, n, depth)
	case []string:
		b.WriteByte('[')
		for i, s := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := jcsString(b, s); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := jcsValue(b, e, depth+1); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case map[string]string:
		m := make(map[string]any, len(x))
		for k, s := range x {
			m[k] = s
		}
		return jcsValue(b, m, depth)
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			if !utf8.ValidString(k) {
				return errJCS
			}
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return utf16Less(keys[i], keys[j]) })
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := jcsString(b, k); err != nil {
				return err
			}
			b.WriteByte(':')
			if err := jcsValue(b, x[k], depth+1); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return errJCS
	}
	return nil
}

// utf16Less orders by UTF-16 code units, as RFC 8785 §3.2.3 requires.
func utf16Less(a, b string) bool {
	ua, ub := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

// jcsString writes s as ECMAScript's JSON.stringify does (RFC 8785 §3.2.2.2):
// only ", \ and control characters are escaped, the named ones short.
func jcsString(b *bytes.Buffer, s string) error {
	if !utf8.ValidString(s) {
		return errJCS
	}
	const hexDigits = "0123456789abcdef"
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if c < 0x20 {
				b.WriteString(`\u00`)
				b.WriteByte(hexDigits[c>>4])
				b.WriteByte(hexDigits[c&0xf])
			} else {
				b.WriteByte(c)
			}
		}
	}
	b.WriteByte('"')
	return nil
}
