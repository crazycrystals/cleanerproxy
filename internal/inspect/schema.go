package inspect

// A deliberately small JSON Schema validator covering only the subset that
// appears in LLM tool `input_schema` declarations.
//
// Why hand-rolled instead of a library: this code validates attacker-
// influenced input inside a security boundary, and the full JSON Schema spec
// (remote $ref resolution, dynamic anchors, vocabularies) is a large and
// genuinely dangerous surface — remote $ref alone is an SSRF primitive we must
// never have. Supporting only the ~12 keywords that tool schemas actually use
// keeps the trusted computing base auditable in one sitting.
//
// Unsupported keywords are ignored rather than erroring, so an exotic schema
// degrades to weaker validation instead of breaking the proxy. The structural
// inspector compensates by treating "schema too complex to validate" as a
// signal in its own right.

import (
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
)

// SchemaViolation is a single validation failure, located by JSON Pointer.
type SchemaViolation struct {
	Path string // JSON Pointer into the instance, e.g. "/command"
	Msg  string

	// Fatal marks violations the real model essentially cannot produce,
	// because the provider constrains sampling to the declared schema.
	// A wrong type or an undeclared property under additionalProperties:false
	// is strong evidence of post-hoc tampering. A failed `pattern` or a
	// range violation is weaker: those are not always enforced by
	// constrained decoding, so a legitimate model can trip them.
	Fatal bool
}

func (v SchemaViolation) String() string {
	at := v.Path
	if at == "" {
		at = "(root)"
	}
	return fmt.Sprintf("%s: %s", at, v.Msg)
}

// ValidateSchema checks instance against a tool input_schema.
//
// It returns the violations found, plus `understood`, reporting whether the
// schema used only keywords this validator implements. When understood is
// false the absence of violations proves nothing, and callers must not treat
// a clean result as an all-clear.
func ValidateSchema(schema json.RawMessage, instance any) (violations []SchemaViolation, understood bool) {
	if len(schema) == 0 {
		return nil, false
	}
	var s map[string]any
	if err := json.Unmarshal(schema, &s); err != nil {
		return nil, false
	}
	v := &schemaValidator{understood: true}
	v.validate(s, instance, "")
	sort.Slice(v.out, func(i, j int) bool { return v.out[i].Path < v.out[j].Path })
	return v.out, v.understood
}

type schemaValidator struct {
	out        []SchemaViolation
	understood bool
	depth      int
}

// knownKeywords are the keywords this validator actually enforces or can
// safely ignore. Anything outside this set flips `understood` to false.
var knownKeywords = map[string]bool{
	"type": true, "properties": true, "required": true,
	"additionalProperties": true, "enum": true, "const": true,
	"items": true, "prefixItems": true, "minItems": true, "maxItems": true,
	"minLength": true, "maxLength": true, "pattern": true,
	"minimum": true, "maximum": true,
	"exclusiveMinimum": true, "exclusiveMaximum": true,
	"anyOf": true, "oneOf": true, "allOf": true,

	// Annotation-only keywords: no validation effect, safe to ignore.
	"description": true, "title": true, "default": true, "examples": true,
	"$schema": true, "$id": true, "format": true, "deprecated": true,
	"readOnly": true, "writeOnly": true, "nullable": true,
}

const maxSchemaDepth = 64

func (v *schemaValidator) fail(path, msg string, fatal bool) {
	v.out = append(v.out, SchemaViolation{Path: path, Msg: msg, Fatal: fatal})
}

func (v *schemaValidator) validate(schema map[string]any, inst any, path string) {
	if v.depth > maxSchemaDepth {
		// Depth bound guards against a hostile or cyclic schema. Bail out and
		// mark the schema not understood so the caller stays suspicious.
		v.understood = false
		return
	}
	v.depth++
	defer func() { v.depth-- }()

	for k := range schema {
		if !knownKeywords[k] {
			v.understood = false
		}
	}

	if t, ok := schema["type"]; ok {
		if !v.checkType(t, inst, path) {
			// Type is wrong; downstream keyword checks would produce
			// cascading noise, so stop descending this branch.
			return
		}
	}
	if e, ok := schema["enum"].([]any); ok {
		if !containsJSONEqual(e, inst) {
			v.fail(path, fmt.Sprintf("value not in enum %s", compact(e)), true)
		}
	}
	if c, ok := schema["const"]; ok {
		if !jsonEqual(c, inst) {
			v.fail(path, fmt.Sprintf("value must be const %v", c), true)
		}
	}

	switch x := inst.(type) {
	case map[string]any:
		v.validateObject(schema, x, path)
	case []any:
		v.validateArray(schema, x, path)
	case string:
		v.validateString(schema, x, path)
	default:
		if n, ok := toFloat(inst); ok {
			v.validateNumber(schema, n, path)
		}
	}

	// Composition keywords. `allOf` is enforced; anyOf/oneOf are only
	// checked for total failure, since attributing a violation to one branch
	// produces misleading evidence in a security notice.
	if all, ok := schema["allOf"].([]any); ok {
		for _, sub := range all {
			if sm, ok := sub.(map[string]any); ok {
				v.validate(sm, inst, path)
			}
		}
	}
	for _, key := range []string{"anyOf", "oneOf"} {
		branches, ok := schema[key].([]any)
		if !ok {
			continue
		}
		matched := false
		for _, sub := range branches {
			sm, ok := sub.(map[string]any)
			if !ok {
				continue
			}
			probe := &schemaValidator{understood: true, depth: v.depth}
			probe.validate(sm, inst, path)
			if len(probe.out) == 0 {
				matched = true
				break
			}
		}
		if !matched && len(branches) > 0 {
			v.fail(path, fmt.Sprintf("value does not match any %s branch", key), true)
		}
	}
}

func (v *schemaValidator) checkType(t any, inst any, path string) bool {
	var allowed []string
	switch tv := t.(type) {
	case string:
		allowed = []string{tv}
	case []any:
		for _, e := range tv {
			if s, ok := e.(string); ok {
				allowed = append(allowed, s)
			}
		}
	default:
		v.understood = false
		return true
	}
	for _, a := range allowed {
		if matchesType(a, inst) {
			return true
		}
	}
	v.fail(path, fmt.Sprintf("expected type %s, got %s", strings.Join(allowed, "|"), jsonTypeOf(inst)), true)
	return false
}

func matchesType(t string, inst any) bool {
	switch t {
	case "object":
		_, ok := inst.(map[string]any)
		return ok
	case "array":
		_, ok := inst.([]any)
		return ok
	case "string":
		_, ok := inst.(string)
		return ok
	case "boolean":
		_, ok := inst.(bool)
		return ok
	case "null":
		return inst == nil
	case "number":
		_, ok := toFloat(inst)
		return ok
	case "integer":
		f, ok := toFloat(inst)
		return ok && f == math.Trunc(f) && !math.IsInf(f, 0)
	}
	return true // unknown type name: do not claim a violation
}

func jsonTypeOf(inst any) string {
	switch inst.(type) {
	case map[string]any:
		return "object"
	case []any:
		return "array"
	case string:
		return "string"
	case bool:
		return "boolean"
	case nil:
		return "null"
	}
	if _, ok := toFloat(inst); ok {
		return "number"
	}
	return "unknown"
}

func (v *schemaValidator) validateObject(schema map[string]any, obj map[string]any, path string) {
	props, _ := schema["properties"].(map[string]any)

	if req, ok := schema["required"].([]any); ok {
		for _, r := range req {
			name, ok := r.(string)
			if !ok {
				continue
			}
			if _, present := obj[name]; !present {
				v.fail(join(path, name), "required property missing", true)
			}
		}
	}

	// Undeclared properties are the highest-signal tampering indicator in
	// this whole validator: constrained decoding at the provider will not
	// emit a key outside `properties`, so an extra key means something
	// downstream of the model edited the object.
	addl, hasAddl := schema["additionalProperties"]
	addlAllowed := true
	var addlSchema map[string]any
	if hasAddl {
		switch a := addl.(type) {
		case bool:
			addlAllowed = a
		case map[string]any:
			addlSchema = a
		}
	}
	if props != nil {
		keys := make([]string, 0, len(obj))
		for k := range obj {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			sub, declared := props[k]
			if !declared {
				switch {
				case !addlAllowed:
					v.fail(join(path, k), "undeclared property (schema sets additionalProperties:false)", true)
				case addlSchema != nil:
					v.validate(addlSchema, obj[k], join(path, k))
				default:
					// Schema is silent on extra properties. Still worth
					// reporting, but non-fatal: a permissive schema makes
					// this weak evidence on its own.
					v.fail(join(path, k), "property not present in declared schema", false)
				}
				continue
			}
			if sm, ok := sub.(map[string]any); ok {
				v.validate(sm, obj[k], join(path, k))
			}
		}
	}
}

func (v *schemaValidator) validateArray(schema map[string]any, arr []any, path string) {
	if m, ok := toFloat(schema["minItems"]); ok && float64(len(arr)) < m {
		v.fail(path, fmt.Sprintf("array shorter than minItems %v", m), false)
	}
	if m, ok := toFloat(schema["maxItems"]); ok && float64(len(arr)) > m {
		v.fail(path, fmt.Sprintf("array longer than maxItems %v", m), false)
	}
	if items, ok := schema["items"].(map[string]any); ok {
		for i, e := range arr {
			v.validate(items, e, fmt.Sprintf("%s/%d", path, i))
		}
	}
	if pre, ok := schema["prefixItems"].([]any); ok {
		for i, sub := range pre {
			if i >= len(arr) {
				break
			}
			if sm, ok := sub.(map[string]any); ok {
				v.validate(sm, arr[i], fmt.Sprintf("%s/%d", path, i))
			}
		}
	}
}

func (v *schemaValidator) validateString(schema map[string]any, s string, path string) {
	// Length and pattern are non-fatal: providers do not reliably enforce
	// them during constrained decoding, so a real model can violate them.
	if m, ok := toFloat(schema["minLength"]); ok && float64(len([]rune(s))) < m {
		v.fail(path, fmt.Sprintf("string shorter than minLength %v", m), false)
	}
	if m, ok := toFloat(schema["maxLength"]); ok && float64(len([]rune(s))) > m {
		v.fail(path, fmt.Sprintf("string longer than maxLength %v", m), false)
	}
	if p, ok := schema["pattern"].(string); ok {
		// Compile failures are the schema author's problem, not a finding.
		if re, err := regexp.Compile(p); err == nil && !re.MatchString(s) {
			v.fail(path, fmt.Sprintf("string does not match pattern %q", p), false)
		}
	}
}

func (v *schemaValidator) validateNumber(schema map[string]any, n float64, path string) {
	if m, ok := toFloat(schema["minimum"]); ok && n < m {
		v.fail(path, fmt.Sprintf("value below minimum %v", m), false)
	}
	if m, ok := toFloat(schema["maximum"]); ok && n > m {
		v.fail(path, fmt.Sprintf("value above maximum %v", m), false)
	}
	if m, ok := toFloat(schema["exclusiveMinimum"]); ok && n <= m {
		v.fail(path, fmt.Sprintf("value not above exclusiveMinimum %v", m), false)
	}
	if m, ok := toFloat(schema["exclusiveMaximum"]); ok && n >= m {
		v.fail(path, fmt.Sprintf("value not below exclusiveMaximum %v", m), false)
	}
}

// toFloat normalizes the several numeric shapes that can reach us: float64
// from a plain unmarshal, json.Number when the decoder preserves precision,
// and the int kinds when schemas are constructed in Go rather than parsed.
func toFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	}
	return 0, false
}

func jsonEqual(a, b any) bool {
	// Compare by canonical JSON encoding so numeric representation
	// differences (json.Number vs float64) do not cause false mismatches.
	ab, err1 := json.Marshal(a)
	bb, err2 := json.Marshal(b)
	if err1 != nil || err2 != nil {
		return false
	}
	return string(ab) == string(bb)
}

func containsJSONEqual(list []any, v any) bool {
	for _, e := range list {
		if jsonEqual(e, v) {
			return true
		}
	}
	return false
}

func compact(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "?"
	}
	if len(b) > 200 {
		return string(b[:200]) + "..."
	}
	return string(b)
}

// join builds a JSON Pointer path, escaping per RFC 6901.
func join(base, key string) string {
	key = strings.ReplaceAll(key, "~", "~0")
	key = strings.ReplaceAll(key, "/", "~1")
	return base + "/" + key
}
