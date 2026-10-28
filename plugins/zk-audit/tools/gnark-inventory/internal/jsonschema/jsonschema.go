// Package jsonschema is a small, dependency-free JSON Schema validator for the
// subset of draft 2020-12 that zk-audit's schemas use: type, properties,
// required, additionalProperties, items, enum, const, pattern, minLength,
// maxLength, minimum, maximum, minItems, maxItems, uniqueItems, oneOf, anyOf,
// allOf, if/then, $ref to local $defs, and $defs. Unknown keywords make
// Compile fail so a schema never silently means less than it says.
package jsonschema

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Schema is a compiled schema node.
type Schema struct {
	root  *Schema
	defs  map[string]*Schema
	ref   string
	bool_ *bool

	types      []string
	properties map[string]*Schema
	required   []string
	addlProps  *Schema
	addlFalse  bool
	items      *Schema
	enum       []any
	hasConst   bool
	constV     any
	pattern    *regexp.Regexp
	minLen     *int
	maxLen     *int
	minimum    *float64
	maximum    *float64
	minItems   *int
	maxItems   *int
	unique     bool
	oneOf      []*Schema
	anyOf      []*Schema
	allOf      []*Schema
	ifS        *Schema
	thenS      *Schema
}

var annotationKeys = map[string]bool{
	"$schema": true, "$id": true, "$comment": true, "title": true, "description": true,
	"examples": true, "default": true, "format": true, "deprecated": true, "readOnly": true,
}

// Compile parses a schema document.
func Compile(doc []byte) (*Schema, error) {
	var v any
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("schema: %w", err)
	}
	root := &Schema{defs: map[string]*Schema{}}
	root.root = root
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("schema: root must be an object")
	}
	if d, ok := m["$defs"].(map[string]any); ok {
		for name := range d {
			root.defs[name] = &Schema{root: root}
		}
		for name, dv := range d {
			if err := root.defs[name].parse(dv, "#/$defs/"+name); err != nil {
				return nil, err
			}
		}
	}
	if err := root.parse(m, "#"); err != nil {
		return nil, err
	}
	// resolve refs eagerly so a bad ref fails at compile time
	var check func(s *Schema) error
	seen := map[*Schema]bool{}
	check = func(s *Schema) error {
		if s == nil || seen[s] {
			return nil
		}
		seen[s] = true
		if s.ref != "" {
			if _, err := s.resolve(); err != nil {
				return err
			}
		}
		for _, c := range s.children() {
			if err := check(c); err != nil {
				return err
			}
		}
		return nil
	}
	if err := check(root); err != nil {
		return nil, err
	}
	for _, d := range root.defs {
		if err := check(d); err != nil {
			return nil, err
		}
	}
	return root, nil
}

func (s *Schema) children() []*Schema {
	var out []*Schema
	for _, p := range s.properties {
		out = append(out, p)
	}
	out = append(out, s.addlProps, s.items, s.ifS, s.thenS)
	out = append(out, s.oneOf...)
	out = append(out, s.anyOf...)
	out = append(out, s.allOf...)
	return out
}

func (s *Schema) resolve() (*Schema, error) {
	if !strings.HasPrefix(s.ref, "#/$defs/") {
		return nil, fmt.Errorf("schema: only local #/$defs refs are supported, got %q", s.ref)
	}
	d, ok := s.root.defs[strings.TrimPrefix(s.ref, "#/$defs/")]
	if !ok {
		return nil, fmt.Errorf("schema: unresolved ref %q", s.ref)
	}
	return d, nil
}

func intOf(v any, at string) (*int, error) {
	n, ok := v.(json.Number)
	if !ok {
		return nil, fmt.Errorf("schema %s: want integer", at)
	}
	i, err := strconv.Atoi(n.String())
	if err != nil {
		return nil, fmt.Errorf("schema %s: want integer", at)
	}
	return &i, nil
}

func floatOf(v any, at string) (*float64, error) {
	n, ok := v.(json.Number)
	if !ok {
		return nil, fmt.Errorf("schema %s: want number", at)
	}
	f, err := n.Float64()
	if err != nil {
		return nil, err
	}
	return &f, nil
}

func (s *Schema) sub(v any, at string) (*Schema, error) {
	c := &Schema{root: s.root}
	return c, c.parse(v, at)
}

func (s *Schema) parse(v any, at string) error {
	if b, ok := v.(bool); ok {
		s.bool_ = &b
		return nil
	}
	m, ok := v.(map[string]any)
	if !ok {
		return fmt.Errorf("schema %s: want object or boolean", at)
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		val := m[k]
		here := at + "/" + k
		var err error
		switch k {
		case "$defs":
			if at != "#" {
				return fmt.Errorf("schema %s: $defs only at root", here)
			}
		case "$ref":
			r, ok := val.(string)
			if !ok {
				return fmt.Errorf("schema %s: want string", here)
			}
			s.ref = r
		case "type":
			switch t := val.(type) {
			case string:
				s.types = []string{t}
			case []any:
				for _, x := range t {
					xs, ok := x.(string)
					if !ok {
						return fmt.Errorf("schema %s: want string", here)
					}
					s.types = append(s.types, xs)
				}
			default:
				return fmt.Errorf("schema %s: want string or array", here)
			}
		case "properties":
			pm, ok := val.(map[string]any)
			if !ok {
				return fmt.Errorf("schema %s: want object", here)
			}
			s.properties = map[string]*Schema{}
			for pk, pv := range pm {
				if s.properties[pk], err = s.sub(pv, here+"/"+pk); err != nil {
					return err
				}
			}
		case "required":
			arr, ok := val.([]any)
			if !ok {
				return fmt.Errorf("schema %s: want array", here)
			}
			for _, x := range arr {
				xs, ok := x.(string)
				if !ok {
					return fmt.Errorf("schema %s: want strings", here)
				}
				s.required = append(s.required, xs)
			}
		case "additionalProperties":
			if b, ok := val.(bool); ok && !b {
				s.addlFalse = true
			} else if s.addlProps, err = s.sub(val, here); err != nil {
				return err
			}
		case "items":
			if s.items, err = s.sub(val, here); err != nil {
				return err
			}
		case "enum":
			arr, ok := val.([]any)
			if !ok {
				return fmt.Errorf("schema %s: want array", here)
			}
			s.enum = arr
		case "const":
			s.hasConst, s.constV = true, val
		case "pattern":
			ps, ok := val.(string)
			if !ok {
				return fmt.Errorf("schema %s: want string", here)
			}
			if s.pattern, err = regexp.Compile(ps); err != nil {
				return fmt.Errorf("schema %s: %w", here, err)
			}
		case "minLength":
			s.minLen, err = intOf(val, here)
		case "maxLength":
			s.maxLen, err = intOf(val, here)
		case "minimum":
			s.minimum, err = floatOf(val, here)
		case "maximum":
			s.maximum, err = floatOf(val, here)
		case "minItems":
			s.minItems, err = intOf(val, here)
		case "maxItems":
			s.maxItems, err = intOf(val, here)
		case "uniqueItems":
			b, ok := val.(bool)
			if !ok {
				return fmt.Errorf("schema %s: want boolean", here)
			}
			s.unique = b
		case "oneOf", "anyOf", "allOf":
			arr, ok := val.([]any)
			if !ok || len(arr) == 0 {
				return fmt.Errorf("schema %s: want non-empty array", here)
			}
			var list []*Schema
			for i, x := range arr {
				c, err := s.sub(x, fmt.Sprintf("%s/%d", here, i))
				if err != nil {
					return err
				}
				list = append(list, c)
			}
			switch k {
			case "oneOf":
				s.oneOf = list
			case "anyOf":
				s.anyOf = list
			default:
				s.allOf = list
			}
		case "if":
			s.ifS, err = s.sub(val, here)
		case "then":
			s.thenS, err = s.sub(val, here)
		default:
			if !annotationKeys[k] {
				return fmt.Errorf("schema %s: unsupported keyword %q", at, k)
			}
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// Error is one validation failure.
type Error struct {
	Path    string
	Message string
}

func (e Error) Error() string { return e.Path + ": " + e.Message }

// ValidateBytes decodes doc and validates it.
func (s *Schema) ValidateBytes(doc []byte) ([]Error, any, error) {
	var v any
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return nil, nil, fmt.Errorf("invalid JSON: %w", err)
	}
	if dec.More() {
		return nil, nil, fmt.Errorf("invalid JSON: trailing data")
	}
	var errs []Error
	s.validate(v, "$", &errs)
	return errs, v, nil
}

func typeOf(v any) string {
	switch x := v.(type) {
	case nil:
		return "null"
	case bool:
		return "boolean"
	case string:
		return "string"
	case json.Number:
		if _, err := strconv.ParseInt(x.String(), 10, 64); err == nil {
			return "integer"
		}
		if f, err := x.Float64(); err == nil && f == math.Trunc(f) && !strings.ContainsAny(x.String(), ".eE") {
			return "integer"
		}
		return "number"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	}
	return "unknown"
}

func typeMatches(want, got string) bool {
	return want == got || (want == "number" && got == "integer")
}

func equal(a, b any) bool {
	ja, _ := json.Marshal(normalize(a))
	jb, _ := json.Marshal(normalize(b))
	return bytes.Equal(ja, jb)
}

func normalize(v any) any {
	switch x := v.(type) {
	case json.Number:
		if f, err := x.Float64(); err == nil {
			return f
		}
	case []any:
		out := make([]any, len(x))
		for i := range x {
			out[i] = normalize(x[i])
		}
		return out
	case map[string]any:
		out := map[string]any{}
		for k, e := range x {
			out[k] = normalize(e)
		}
		return out
	}
	return v
}

func (s *Schema) validate(v any, path string, errs *[]Error) {
	add := func(format string, a ...any) {
		*errs = append(*errs, Error{Path: path, Message: fmt.Sprintf(format, a...)})
	}
	if s.bool_ != nil {
		if !*s.bool_ {
			add("not allowed")
		}
		return
	}
	if s.ref != "" {
		d, err := s.resolve()
		if err != nil {
			add("%v", err)
			return
		}
		d.validate(v, path, errs)
	}
	got := typeOf(v)
	if len(s.types) > 0 {
		ok := false
		for _, t := range s.types {
			if typeMatches(t, got) {
				ok = true
			}
		}
		if !ok {
			add("type %s, want %s", got, strings.Join(s.types, " or "))
			return
		}
	}
	if s.hasConst && !equal(v, s.constV) {
		add("must equal %v", s.constV)
	}
	if s.enum != nil {
		ok := false
		for _, e := range s.enum {
			if equal(v, e) {
				ok = true
			}
		}
		if !ok {
			add("value %s not in enum", short(v))
		}
	}
	switch x := v.(type) {
	case string:
		n := len([]rune(x))
		if s.minLen != nil && n < *s.minLen {
			add("shorter than %d", *s.minLen)
		}
		if s.maxLen != nil && n > *s.maxLen {
			add("longer than %d", *s.maxLen)
		}
		if s.pattern != nil && !s.pattern.MatchString(x) {
			add("does not match %s", s.pattern.String())
		}
	case json.Number:
		f, _ := x.Float64()
		if s.minimum != nil && f < *s.minimum {
			add("below minimum %v", *s.minimum)
		}
		if s.maximum != nil && f > *s.maximum {
			add("above maximum %v", *s.maximum)
		}
	case []any:
		if s.minItems != nil && len(x) < *s.minItems {
			add("fewer than %d items", *s.minItems)
		}
		if s.maxItems != nil && len(x) > *s.maxItems {
			add("more than %d items", *s.maxItems)
		}
		if s.unique {
			for i := range x {
				for j := i + 1; j < len(x); j++ {
					if equal(x[i], x[j]) {
						add("items %d and %d are equal", i, j)
					}
				}
			}
		}
		if s.items != nil {
			for i, e := range x {
				s.items.validate(e, fmt.Sprintf("%s[%d]", path, i), errs)
			}
		}
	case map[string]any:
		for _, r := range s.required {
			if _, ok := x[r]; !ok {
				add("missing required property %q", r)
			}
		}
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if p, ok := s.properties[k]; ok {
				p.validate(x[k], path+"."+k, errs)
			} else if s.addlFalse {
				add("unknown property %q", k)
			} else if s.addlProps != nil {
				s.addlProps.validate(x[k], path+"."+k, errs)
			}
		}
	}
	for _, c := range s.allOf {
		c.validate(v, path, errs)
	}
	if len(s.anyOf) > 0 {
		ok := false
		for _, c := range s.anyOf {
			var e []Error
			c.validate(v, path, &e)
			if len(e) == 0 {
				ok = true
				break
			}
		}
		if !ok {
			add("matches none of anyOf")
		}
	}
	if len(s.oneOf) > 0 {
		var matched []int
		var best []Error
		for i, c := range s.oneOf {
			var e []Error
			c.validate(v, path, &e)
			if len(e) == 0 {
				matched = append(matched, i)
			} else if best == nil || len(e) < len(best) {
				best = e
			}
		}
		switch len(matched) {
		case 1:
		case 0:
			add("matches none of oneOf; closest branch errors follow")
			*errs = append(*errs, best...)
		default:
			add("matches %d oneOf branches, want exactly 1", len(matched))
		}
	}
	if s.ifS != nil {
		var e []Error
		s.ifS.validate(v, path, &e)
		if len(e) == 0 && s.thenS != nil {
			s.thenS.validate(v, path, errs)
		}
	}
}

func short(v any) string {
	b, _ := json.Marshal(v)
	if len(b) > 60 {
		return string(b[:57]) + "..."
	}
	return string(b)
}
