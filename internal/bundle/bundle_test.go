package bundle

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

var when = time.Date(2026, 9, 14, 17, 2, 11, 0, time.UTC)

func mkVar(name, value, item string) Var {
	return Var{
		Name:        name,
		Value:       value,
		AccountUUID: "acct-" + item,
		UserUUID:    "user-" + item,
		AccountURL:  "my.1password.com",
		ItemID:      "item-" + item,
		FieldID:     "field-" + item,
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	in := Bundle{
		Schema:      Schema,
		GeneratedAt: when,
		Vars:        []Var{mkVar("B_VAR", "b", "1"), mkVar("A_VAR", "a", "2")},
	}
	data, err := Encode(in)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	out, err := Decode(data)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	want := in
	want.Vars = []Var{mkVar("A_VAR", "a", "2"), mkVar("B_VAR", "b", "1")}
	if !reflect.DeepEqual(out, want) {
		t.Errorf("round trip mismatch\n got %+v\nwant %+v", out, want)
	}
	// Encode must not reorder the caller's slice.
	if in.Vars[0].Name != "B_VAR" {
		t.Error("Encode mutated input slice")
	}
}

func TestEncodeIsDeterministic(t *testing.T) {
	a := Bundle{Schema: Schema, GeneratedAt: when, Vars: []Var{mkVar("Z", "1", "1"), mkVar("A", "2", "2")}}
	b := Bundle{Schema: Schema, GeneratedAt: when, Vars: []Var{mkVar("A", "2", "2"), mkVar("Z", "1", "1")}}
	ea, _ := Encode(a)
	eb, _ := Encode(b)
	if string(ea) != string(eb) {
		t.Error("same bundle, different var order, different encoding")
	}
}

func TestEncodeIsBase64OfJSON(t *testing.T) {
	data, err := Encode(Bundle{Schema: Schema, GeneratedAt: when, Vars: []Var{mkVar("X", "v", "1")}})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		t.Fatalf("not std base64: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	for _, k := range []string{"schema", "generated_at", "vars"} {
		if _, ok := m[k]; !ok {
			t.Errorf("missing key %q", k)
		}
	}
	v := m["vars"].([]any)[0].(map[string]any)
	for _, k := range []string{"name", "value", "account_uuid", "user_uuid", "account_url", "item_id", "field_id"} {
		if _, ok := v[k]; !ok {
			t.Errorf("var missing key %q", k)
		}
	}
	if !strings.Contains(string(raw), `"generated_at":"2026-09-14T17:02:11Z"`) {
		t.Errorf("generated_at not RFC3339 UTC: %s", raw)
	}
}

func TestEncodeSetsSchema(t *testing.T) {
	data, err := Encode(Bundle{GeneratedAt: when})
	if err != nil {
		t.Fatal(err)
	}
	out, err := Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	if out.Schema != Schema {
		t.Errorf("schema = %d, want %d", out.Schema, Schema)
	}
	if out.Vars == nil {
		t.Error("Vars decoded as nil, want empty slice")
	}
}

func TestDecodeErrors(t *testing.T) {
	b64 := func(s string) []byte { return []byte(base64.StdEncoding.EncodeToString([]byte(s))) }
	tests := []struct {
		name string
		data []byte
		want error
	}{
		{"bad base64", []byte("!!!not-base64!!!"), ErrBadBase64},
		{"empty", []byte(""), ErrBadJSON},
		{"bad json", b64(`{"schema":`), ErrBadJSON},
		{"json wrong type", b64(`[]`), ErrBadJSON},
		{"schema 0", b64(`{"schema":0,"vars":[]}`), ErrUnknownSchema},
		{"schema 2", b64(`{"schema":2,"vars":[]}`), ErrUnknownSchema},
		{"schema only", b64(`{"schema":1}`), ErrBadJSON},
		{"vars null", b64(`{"schema":1,"generated_at":"2026-09-14T17:02:11Z","vars":null}`), ErrBadJSON},
		{"vars missing", b64(`{"schema":1,"generated_at":"2026-09-14T17:02:11Z"}`), ErrBadJSON},
		{"generated_at missing", b64(`{"schema":1,"vars":[]}`), ErrBadJSON},
		{"generated_at null", b64(`{"schema":1,"generated_at":null,"vars":[]}`), ErrBadJSON},
		{"generated_at zero", b64(`{"schema":1,"generated_at":"0001-01-01T00:00:00Z","vars":[]}`), ErrBadJSON},
		{"generated_at malformed", b64(`{"schema":1,"generated_at":"yesterday","vars":[]}`), ErrBadJSON},
		{"generated_at wrong type", b64(`{"schema":1,"generated_at":5,"vars":[]}`), ErrBadJSON},
		{"invalid utf8 in value", b64("{\"schema\":1,\"generated_at\":\"2026-09-14T17:02:11Z\",\"vars\":[{\"name\":\"A\",\"value\":\"\xff\"}]}"), ErrBadJSON},
		{"invalid utf8 outside strings", b64("{\"schema\":1\xff}"), ErrBadJSON},
		{"vars wrong type", b64(`{"schema":1,"generated_at":"2026-09-14T17:02:11Z","vars":{}}`), ErrBadJSON},
		{"null var entry", b64(`{"schema":1,"generated_at":"2026-09-14T17:02:11Z","vars":[null]}`), ErrBadJSON},
		{"null var entry after a good one", b64(`{"schema":1,"generated_at":"2026-09-14T17:02:11Z","vars":[` + goodVarJSON("A") + `,null]}`), ErrBadJSON},
		{"var missing value", b64(varsJSON(`{"name":"A","account_uuid":"a","user_uuid":"u","account_url":"my.1password.com","item_id":"i","field_id":"f"}`)), ErrBadJSON},
		{"var null value", b64(varsJSON(`{"name":"A","value":null,"account_uuid":"a","user_uuid":"u","account_url":"my.1password.com","item_id":"i","field_id":"f"}`)), ErrBadJSON},
		{"var value wrong type", b64(varsJSON(`{"name":"A","value":5,"account_uuid":"a","user_uuid":"u","account_url":"my.1password.com","item_id":"i","field_id":"f"}`)), ErrBadJSON},
		{"var empty name", b64(varsJSON(`{"name":"","value":"v","account_uuid":"a","user_uuid":"u","account_url":"my.1password.com","item_id":"i","field_id":"f"}`)), ErrBadJSON},
		{"var missing name", b64(varsJSON(`{"value":"v","account_uuid":"a","user_uuid":"u","account_url":"my.1password.com","item_id":"i","field_id":"f"}`)), ErrBadJSON},
		{"var empty account_uuid", b64(varsJSON(`{"name":"A","value":"v","account_uuid":"","user_uuid":"u","account_url":"my.1password.com","item_id":"i","field_id":"f"}`)), ErrBadJSON},
		{"var empty user_uuid", b64(varsJSON(`{"name":"A","value":"v","account_uuid":"a","user_uuid":"","account_url":"my.1password.com","item_id":"i","field_id":"f"}`)), ErrBadJSON},
		{"var empty account_url", b64(varsJSON(`{"name":"A","value":"v","account_uuid":"a","user_uuid":"u","account_url":"","item_id":"i","field_id":"f"}`)), ErrBadJSON},
		{"var empty item_id", b64(varsJSON(`{"name":"A","value":"v","account_uuid":"a","user_uuid":"u","account_url":"my.1password.com","item_id":"","field_id":"f"}`)), ErrBadJSON},
		{"var empty field_id", b64(varsJSON(`{"name":"A","value":"v","account_uuid":"a","user_uuid":"u","account_url":"my.1password.com","item_id":"i","field_id":""}`)), ErrBadJSON},
		{"var missing field_id", b64(varsJSON(`{"name":"A","value":"v","account_uuid":"a","user_uuid":"u","account_url":"my.1password.com","item_id":"i"}`)), ErrBadJSON},
		{"duplicate names", b64(varsJSON(goodVarJSON("A") + `,` + goodVarJSON("A"))), ErrBadJSON},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Decode(tc.data)
			if !errors.Is(err, tc.want) {
				t.Errorf("Decode() error = %v, want errors.Is %v", err, tc.want)
			}
		})
	}
}

// goodVarJSON is one fully populated var entry named name.
func goodVarJSON(name string) string {
	return `{"name":"` + name + `","value":"v","account_uuid":"a","user_uuid":"u","account_url":"my.1password.com","item_id":"i-` + name + `","field_id":"f"}`
}

// varsJSON wraps entries in an otherwise valid bundle document.
func varsJSON(entries string) string {
	return `{"schema":1,"generated_at":"2026-09-14T17:02:11Z","vars":[` + entries + `]}`
}

func TestDecodeAcceptsEmptyValueAndEmptyVars(t *testing.T) {
	// An empty value is rejected at sync, not here; a bundle carrying one is
	// still well-formed.
	b64 := func(s string) []byte { return []byte(base64.StdEncoding.EncodeToString([]byte(s))) }
	for name, doc := range map[string]string{
		"empty vars":  varsJSON(``),
		"empty value": varsJSON(`{"name":"A","value":"","account_uuid":"a","user_uuid":"u","account_url":"my.1password.com","item_id":"i","field_id":"f"}`),
		"two vars":    varsJSON(goodVarJSON("A") + `,` + goodVarJSON("B")),
	} {
		t.Run(name, func(t *testing.T) {
			b, err := Decode(b64(doc))
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			if b.Vars == nil {
				t.Fatal("Vars is nil")
			}
		})
	}
}

func TestDecodeVarErrorsNeverQuoteContent(t *testing.T) {
	const mark = "MARKER-7f3a"
	b64 := func(s string) []byte { return []byte(base64.StdEncoding.EncodeToString([]byte(s))) }
	for name, doc := range map[string]string{
		"missing value":  varsJSON(`{"name":"` + mark + `","account_uuid":"a","user_uuid":"u","account_url":"x","item_id":"i","field_id":"f"}`),
		"duplicate name": varsJSON(goodVarJSON(mark) + `,` + goodVarJSON(mark)),
		"empty item_id":  varsJSON(`{"name":"` + mark + `","value":"` + mark + `","account_uuid":"a","user_uuid":"u","account_url":"x","item_id":"","field_id":"f"}`),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Decode(b64(doc))
			if err == nil {
				t.Fatal("want error")
			}
			if strings.Contains(err.Error(), mark) {
				t.Errorf("error text carries bundle content: %q", err.Error())
			}
		})
	}
}

func TestEncodeRefusesWhatDecodeRejects(t *testing.T) {
	good := mkVar("A", "v", "1")
	with := func(mut func(*Var)) Var { v := good; mut(&v); return v }
	cases := map[string]Bundle{
		"zero generated_at":  {Vars: []Var{good}},
		"empty name":         {GeneratedAt: when, Vars: []Var{with(func(v *Var) { v.Name = "" })}},
		"empty account_uuid": {GeneratedAt: when, Vars: []Var{with(func(v *Var) { v.AccountUUID = "" })}},
		"empty user_uuid":    {GeneratedAt: when, Vars: []Var{with(func(v *Var) { v.UserUUID = "" })}},
		"empty account_url":  {GeneratedAt: when, Vars: []Var{with(func(v *Var) { v.AccountURL = "" })}},
		"empty item_id":      {GeneratedAt: when, Vars: []Var{with(func(v *Var) { v.ItemID = "" })}},
		"empty field_id":     {GeneratedAt: when, Vars: []Var{with(func(v *Var) { v.FieldID = "" })}},
		"duplicate names":    {GeneratedAt: when, Vars: []Var{good, mkVar("A", "other", "2")}},
	}
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			data, err := Encode(b)
			if err == nil {
				_, derr := Decode(data)
				t.Fatalf("Encode accepted a bundle Decode rejects (Decode: %v)", derr)
			}
			if strings.Contains(err.Error(), "other") || strings.Contains(err.Error(), `"v"`) {
				t.Errorf("Encode error carries a value: %q", err.Error())
			}
		})
	}
}

func TestDecodeErrorsNeverQuoteContent(t *testing.T) {
	const mark = "MARKER-7f3a"
	b64 := func(s string) []byte { return []byte(base64.StdEncoding.EncodeToString([]byte(s))) }
	inputs := map[string][]byte{
		"malformed timestamp": b64(`{"schema":1,"generated_at":"` + mark + `","vars":[]}`),
		"syntax error":        b64(`{"schema":1,"generated_at":"2026-09-14T17:02:11Z","vars":[` + mark),
		"wrong type":          b64(`{"schema":"` + mark + `","vars":[]}`),
		"invalid utf8":        b64("{\"schema\":1,\"generated_at\":\"" + mark + "\xff\",\"vars\":[]}"),
		"top-level string":    b64(`"` + mark + `"`),
	}
	for name, data := range inputs {
		t.Run(name, func(t *testing.T) {
			_, err := Decode(data)
			if err == nil {
				t.Fatal("want error")
			}
			if strings.Contains(err.Error(), mark) {
				t.Errorf("error text carries bundle content: %q", err.Error())
			}
		})
	}
}

func TestDiff(t *testing.T) {
	old := Bundle{Vars: []Var{
		mkVar("UNCHANGED", "same", "1"),
		mkVar("CHANGED_VALUE", "old", "2"),
		mkVar("CHANGED_PROVENANCE", "same", "3"),
		mkVar("REMOVED", "gone", "4"),
	}}
	old.Vars[3].AccountURL = "old.1password.com"
	moved := mkVar("CHANGED_PROVENANCE", "same", "3")
	moved.ItemID = "item-other"
	cur := Bundle{Vars: []Var{
		mkVar("ADDED", "new", "5"),
		mkVar("UNCHANGED", "same", "1"),
		mkVar("CHANGED_VALUE", "new", "2"),
		moved,
	}}
	got := Diff(old, cur)
	want := []Row{
		{Name: "ADDED", AccountURL: "my.1password.com", Status: Added},
		{Name: "CHANGED_PROVENANCE", AccountURL: "my.1password.com", Status: Changed},
		{Name: "CHANGED_VALUE", AccountURL: "my.1password.com", Status: Changed},
		{Name: "REMOVED", AccountURL: "old.1password.com", Status: Removed},
		{Name: "UNCHANGED", AccountURL: "my.1password.com", Status: Unchanged},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Diff\n got %+v\nwant %+v", got, want)
	}
}

func TestDiffEmpty(t *testing.T) {
	if got := Diff(Bundle{}, Bundle{}); len(got) != 0 {
		t.Errorf("Diff of empties = %+v, want none", got)
	}
}

func TestCompare(t *testing.T) {
	b := Bundle{Vars: []Var{
		mkVar("OK", "same", "1"),
		mkVar("DIFFERENT", "old", "2"),
		mkVar("STALE", "gone", "3"),
	}}
	b.Vars[2].AccountURL = "stale.1password.com"
	resolved := []Var{
		mkVar("MISSING", "new", "4"),
		mkVar("DIFFERENT", "new", "2"),
		mkVar("OK", "same", "1"),
	}
	got := Compare(b, resolved)
	want := []Row{
		{Name: "DIFFERENT", AccountURL: "my.1password.com", Status: Different},
		{Name: "MISSING", AccountURL: "my.1password.com", Status: Missing},
		{Name: "OK", AccountURL: "my.1password.com", Status: OK},
		{Name: "STALE", AccountURL: "stale.1password.com", Status: Stale},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Compare\n got %+v\nwant %+v", got, want)
	}
}

func TestCompareProvenanceOnlyChangeIsDifferent(t *testing.T) {
	b := Bundle{Vars: []Var{mkVar("X", "same", "1")}}
	r := mkVar("X", "same", "1")
	r.FieldID = "field-new"
	got := Compare(b, []Var{r})
	if len(got) != 1 || got[0].Status != Different {
		t.Errorf("Compare = %+v, want one different row", got)
	}
}
