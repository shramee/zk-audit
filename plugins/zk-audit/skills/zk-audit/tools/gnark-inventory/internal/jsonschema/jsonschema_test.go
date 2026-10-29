package jsonschema

import "testing"

func TestCompileRejectsUnknownKeyword(t *testing.T) {
	if _, err := Compile([]byte(`{"type":"object","patternProperties":{}}`)); err == nil {
		t.Fatal("unknown keyword must fail compilation")
	}
	if _, err := Compile([]byte(`{"$ref":"#/$defs/missing"}`)); err == nil {
		t.Fatal("unresolved ref must fail compilation")
	}
}

func TestValidate(t *testing.T) {
	s, err := Compile([]byte(`{
	  "type":"object","required":["a"],"additionalProperties":false,
	  "properties":{
	    "a":{"type":"integer","minimum":1,"maximum":3},
	    "b":{"type":"array","items":{"$ref":"#/$defs/s"},"uniqueItems":true,"minItems":1},
	    "c":{"oneOf":[{"const":"x"},{"type":"integer"}]}
	  },
	  "$defs":{"s":{"type":"string","pattern":"^[a-z]+$"}}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]int{
		`{"a":2}`:                       0,
		`{"a":2,"b":["x","y"],"c":"x"}`: 0,
		`{"a":2,"c":5}`:                 0,
		`{}`:                            1,
		`{"a":4}`:                       1,
		`{"a":1.5}`:                     1,
		`{"a":1,"z":1}`:                 1,
		`{"a":1,"b":["x","x"]}`:         1,
		`{"a":1,"b":["X"]}`:             1,
		`{"a":1,"b":[]}`:                1,
		`{"a":1,"c":"y"}`:               1,
	}
	for doc, want := range cases {
		errs, _, err := s.ValidateBytes([]byte(doc))
		if err != nil {
			t.Fatal(err)
		}
		if (len(errs) > 0) != (want > 0) {
			t.Errorf("%s: errors %v, want failure=%v", doc, errs, want > 0)
		}
	}
	if _, _, err := s.ValidateBytes([]byte(`{"a":1} {}`)); err == nil {
		t.Error("trailing data must fail")
	}
}
