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
