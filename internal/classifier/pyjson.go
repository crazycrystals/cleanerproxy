package classifier

// Python-compatible JSON serialization.
//
// Granite Guardian's function-calling data was produced with Python's
// json.dumps defaults: ", " and ": " separators, ensure_ascii escaping of every
// non-ASCII character as \uXXXX, no HTML escaping, and objects emitted in
// insertion order. Go's encoding/json differs on all four points (compact
// separators, raw UTF-8, HTML-escaped <>&, sorted map keys).
//
// A small classifier's accuracy depends on seeing inputs shaped like its
// training data, so this file reproduces the Python form rather than feeding
// the model Go's encoding.
//
// There is also a security side effect worth keeping: ensure_ascii turns every
// invisible or confusable character (zero-width joiners, bidi overrides,
// Cyrillic homoglyphs) into a visible \uXXXX escape, so the model sees what an
// attacker is trying to hide rather than a rendered lookalike.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode/utf16"
)

// orderedObject is a JSON object that remembers key insertion order.
type orderedObject struct {
	keys []string
	vals map[string]any
}

func newOrdered() *orderedObject { return &orderedObject{vals: map[string]any{}} }

// set appends a key, or updates it in place if already present. This matches
// Python dict semantics: a repeated key keeps its first position and takes the
// last value, which is also what json.loads does with duplicate keys.
func (o *orderedObject) set(k string, v any) *orderedObject {
	if _, exists := o.vals[k]; !exists {
		o.keys = append(o.keys, k)
	}
	o.vals[k] = v
	return o
}

func (o *orderedObject) get(k string) (any, bool) {
	v, ok := o.vals[k]
	return v, ok
}

// decodeOrdered parses JSON preserving object key order and exact numeric
// literals.
func decodeOrdered(raw []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	v, err := decodeValue(dec, 0)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing data after JSON value")
	}
	return v, nil
}

// maxDecodeDepth bounds nesting. Arguments come from a hostile upstream, and
// unbounded recursion on deeply nested input is a trivial stack exhaustion.
const maxDecodeDepth = 128

func decodeValue(dec *json.Decoder, depth int) (any, error) {
	if depth > maxDecodeDepth {
		return nil, errors.New("JSON nesting too deep")
	}
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	d, isDelim := tok.(json.Delim)
	if !isDelim {
		return tok, nil // string, json.Number, bool, or nil
	}
	switch d {
	case '{':
		obj := newOrdered()
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return nil, err
			}
			key, ok := kt.(string)
			if !ok {
				return nil, fmt.Errorf("object key is %T, not string", kt)
			}
			val, err := decodeValue(dec, depth+1)
			if err != nil {
				return nil, err
			}
			obj.set(key, val)
		}
		if _, err := dec.Token(); err != nil {
			return nil, err
		}
		return obj, nil
	case '[':
		arr := []any{}
		for dec.More() {
			val, err := decodeValue(dec, depth+1)
			if err != nil {
				return nil, err
			}
			arr = append(arr, val)
		}
		if _, err := dec.Token(); err != nil {
			return nil, err
		}
		return arr, nil
	}
	return nil, fmt.Errorf("unexpected delimiter %q", d)
}

// pyDumps renders v the way Python's json.dumps(v) would.
func pyDumps(v any) string {
	var b strings.Builder
	writePy(&b, v)
	return b.String()
}

func writePy(b *strings.Builder, v any) {
	switch t := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if t {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case json.Number:
		// The original literal is preserved. Python would reformat some
		// float literals (1e3 -> 1000.0), which has no bearing on a
		// relevance judgment and is not worth reproducing.
		b.WriteString(t.String())
	case float64:
		fmt.Fprintf(b, "%v", t)
	case int:
		fmt.Fprintf(b, "%d", t)
	case string:
		writePyString(b, t)
	case []any:
		b.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				b.WriteString(", ")
			}
			writePy(b, e)
		}
		b.WriteByte(']')
	case *orderedObject:
		b.WriteByte('{')
		for i, k := range t.keys {
			if i > 0 {
				b.WriteString(", ")
			}
			writePyString(b, k)
			b.WriteString(": ")
			writePy(b, t.vals[k])
		}
		b.WriteByte('}')
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteString(", ")
			}
			writePyString(b, k)
			b.WriteString(": ")
			writePy(b, t[k])
		}
		b.WriteByte('}')
	default:
		writePyString(b, fmt.Sprint(t))
	}
}

// writePyString emits a JSON string with Python's ensure_ascii=True escaping.
func writePyString(b *strings.Builder, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		default:
			switch {
			case r < 0x20 || r == 0x7f:
				// CPython's ensure_ascii passes only printable ASCII
				// (0x20-0x7e) through; DEL is escaped along with the C0
				// controls. Verified against json.dumps directly.
				fmt.Fprintf(b, `\u%04x`, r)
			case r < 0x7f:
				b.WriteRune(r)
			case r <= 0xFFFF:
				fmt.Fprintf(b, `\u%04x`, r)
			default:
				hi, lo := utf16.EncodeRune(r)
				fmt.Fprintf(b, `\u%04x\u%04x`, hi, lo)
			}
		}
	}
	b.WriteByte('"')
}
