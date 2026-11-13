package bundle

import (
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
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
		VaultID:     "vault-" + item,
		ItemID:      "item-" + item,
		FieldID:     "field-" + item,
	}
}

// sources returns the source of each var.
func sources(vars ...Var) []Source {
	out := make([]Source, len(vars))
	for i, v := range vars {
		out[i] = v.Source()
	}
	return out
}

// mk builds a bundle that trusts exactly its vars.
func mk(vars ...Var) Bundle {
	return Bundle{Schema: Schema, GeneratedAt: when, TrustedSources: sources(vars...), Vars: vars}
}

func b64(s string) []byte { return []byte(base64.StdEncoding.EncodeToString([]byte(s))) }

func TestEncodeDecodeRoundTrip(t *testing.T) {
	in := mk(mkVar("B_VAR", "b", "1"), mkVar("A_VAR", "a", "2"))
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
	want.TrustedSources = sources(want.Vars...)
	if !reflect.DeepEqual(out, want) {
		t.Errorf("round trip mismatch\n got %+v\nwant %+v", out, want)
	}
	// Encode must not reorder the caller's slice.
	if in.Vars[0].Name != "B_VAR" || in.TrustedSources[0].Name != "B_VAR" {
		t.Error("Encode mutated input slice")
	}
}

func TestEncodeIsDeterministic(t *testing.T) {
	a := mk(mkVar("Z", "1", "1"), mkVar("A", "2", "2"))
	b := mk(mkVar("A", "2", "2"), mkVar("Z", "1", "1"))
	// Trusted source order must not matter either.
	slices.Reverse(b.TrustedSources)
	b.TrustedSources = append(b.TrustedSources, Source{"a", "u", "v", "i", "f", "A"})
	a.TrustedSources = append([]Source{{"a", "u", "v", "i", "f", "A"}}, a.TrustedSources...)
	ea, _ := Encode(a)
	eb, _ := Encode(b)
	if string(ea) != string(eb) {
		t.Error("same bundle, different var order, different encoding")
	}
}

func TestEncodeIsBase64OfJSON(t *testing.T) {
	data, err := Encode(mk(mkVar("X", "v", "1")))
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
	if m["schema"] != float64(2) {
		t.Errorf("schema = %v, want 2", m["schema"])
	}
	for _, k := range []string{"schema", "generated_at", "trusted_sources", "vars"} {
		if _, ok := m[k]; !ok {
			t.Errorf("missing key %q", k)
		}
	}
	v := m["vars"].([]any)[0].(map[string]any)
	for _, k := range []string{"name", "value", "account_uuid", "user_uuid", "account_url", "vault_id", "item_id", "field_id"} {
		if _, ok := v[k]; !ok {
			t.Errorf("var missing key %q", k)
		}
	}
	ts := m["trusted_sources"].([]any)[0].(map[string]any)
	if len(ts) != 6 {
		t.Errorf("trusted source has %d keys, want 6: %v", len(ts), ts)
	}
	for _, k := range []string{"account_uuid", "user_uuid", "vault_id", "item_id", "field_id", "name"} {
		if _, ok := ts[k]; !ok {
			t.Errorf("trusted source missing key %q", k)
		}
	}
	if strings.Contains(string(raw), "src_") {
		t.Errorf("the derived source id must not be stored: %s", raw)
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
	if out.Vars == nil || out.TrustedSources == nil {
		t.Error("Vars or TrustedSources decoded as nil, want empty slices")
	}
}

func TestDecodeErrors(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want error
	}{
		{"bad base64", []byte("!!!not-base64!!!"), ErrBadBase64},
		{"empty", []byte(""), ErrBadJSON},
		{"bad json", b64(`{"schema":`), ErrBadJSON},
		{"json wrong type", b64(`[]`), ErrBadJSON},
		{"schema 0", b64(`{"schema":0,"trusted_sources":[],"vars":[]}`), ErrUnknownSchema},
		{"schema 3", b64(`{"schema":3,"trusted_sources":[],"vars":[]}`), ErrUnknownSchema},
		{"schema missing", b64(`{"generated_at":"2026-09-14T17:02:11Z","trusted_sources":[],"vars":[]}`), ErrUnknownSchema},
		{"schema 1", b64(legacyJSON(legacyVarJSON("A"))), ErrLegacySchema},
		{"schema 1 with nothing else", b64(`{"schema":1}`), ErrLegacySchema},
		{"schema 1 dressed as schema 2", b64(`{"schema":1,"generated_at":"2026-09-14T17:02:11Z","trusted_sources":[` + sourceJSON("A") + `],"vars":[` + goodVarJSON("A") + `]}`), ErrLegacySchema},
		{"schema only", b64(`{"schema":2}`), ErrBadJSON},
		{"vars null", b64(`{"schema":2,"generated_at":"2026-09-14T17:02:11Z","trusted_sources":[],"vars":null}`), ErrBadJSON},
		{"vars missing", b64(`{"schema":2,"generated_at":"2026-09-14T17:02:11Z"}`), ErrBadJSON},
		{"generated_at missing", b64(`{"schema":2,"trusted_sources":[],"vars":[]}`), ErrBadJSON},
		{"generated_at null", b64(`{"schema":2,"generated_at":null,"trusted_sources":[],"vars":[]}`), ErrBadJSON},
		{"generated_at zero", b64(`{"schema":2,"generated_at":"0001-01-01T00:00:00Z","trusted_sources":[],"vars":[]}`), ErrBadJSON},
		{"generated_at malformed", b64(`{"schema":2,"generated_at":"yesterday","trusted_sources":[],"vars":[]}`), ErrBadJSON},
		{"generated_at wrong type", b64(`{"schema":2,"generated_at":5,"trusted_sources":[],"vars":[]}`), ErrBadJSON},
		{"invalid utf8 in value", b64("{\"schema\":2,\"generated_at\":\"2026-09-14T17:02:11Z\",\"trusted_sources\":[],\"vars\":[{\"name\":\"A\",\"value\":\"\xff\"}]}"), ErrBadJSON},
		{"invalid utf8 outside strings", b64("{\"schema\":2\xff}"), ErrBadJSON},
		{"vars wrong type", b64(`{"schema":2,"generated_at":"2026-09-14T17:02:11Z","trusted_sources":[],"vars":{}}`), ErrBadJSON},
		{"null var entry", b64(`{"schema":2,"generated_at":"2026-09-14T17:02:11Z","trusted_sources":[],"vars":[null]}`), ErrBadJSON},
		{"null var entry after a good one", b64(`{"schema":2,"generated_at":"2026-09-14T17:02:11Z","trusted_sources":[],"vars":[` + goodVarJSON("A") + `,null]}`), ErrBadJSON},
		{"var missing value", b64(varsJSON(`{"name":"A","account_uuid":"a","user_uuid":"u","account_url":"my.1password.com","vault_id":"v","item_id":"i","field_id":"f"}`)), ErrBadJSON},
		{"var null value", b64(varsJSON(`{"name":"A","value":null,"account_uuid":"a","user_uuid":"u","account_url":"my.1password.com","vault_id":"v","item_id":"i","field_id":"f"}`)), ErrBadJSON},
		{"var value wrong type", b64(varsJSON(`{"name":"A","value":5,"account_uuid":"a","user_uuid":"u","account_url":"my.1password.com","vault_id":"v","item_id":"i","field_id":"f"}`)), ErrBadJSON},
		{"var empty name", b64(varsJSON(`{"name":"","value":"v","account_uuid":"a","user_uuid":"u","account_url":"my.1password.com","vault_id":"v","item_id":"i","field_id":"f"}`)), ErrBadJSON},
		{"var missing name", b64(varsJSON(`{"value":"v","account_uuid":"a","user_uuid":"u","account_url":"my.1password.com","vault_id":"v","item_id":"i","field_id":"f"}`)), ErrBadJSON},
		{"var empty account_uuid", b64(varsJSON(`{"name":"A","value":"v","account_uuid":"","user_uuid":"u","account_url":"my.1password.com","vault_id":"v","item_id":"i","field_id":"f"}`)), ErrBadJSON},
		{"var empty user_uuid", b64(varsJSON(`{"name":"A","value":"v","account_uuid":"a","user_uuid":"","account_url":"my.1password.com","vault_id":"v","item_id":"i","field_id":"f"}`)), ErrBadJSON},
		{"var empty account_url", b64(varsJSON(`{"name":"A","value":"v","account_uuid":"a","user_uuid":"u","account_url":"","vault_id":"v","item_id":"i","field_id":"f"}`)), ErrBadJSON},
		{"var empty item_id", b64(varsJSON(`{"name":"A","value":"v","account_uuid":"a","user_uuid":"u","account_url":"my.1password.com","vault_id":"v","item_id":"","field_id":"f"}`)), ErrBadJSON},
		{"var empty field_id", b64(varsJSON(`{"name":"A","value":"v","account_uuid":"a","user_uuid":"u","account_url":"my.1password.com","vault_id":"v","item_id":"i","field_id":""}`)), ErrBadJSON},
		{"var missing field_id", b64(varsJSON(`{"name":"A","value":"v","account_uuid":"a","user_uuid":"u","account_url":"my.1password.com","vault_id":"v","item_id":"i"}`)), ErrBadJSON},
		{"duplicate names", b64(varsJSON(goodVarJSON("A") + `,` + goodVarJSON("A"))), ErrBadJSON},
		{"var empty vault_id", b64(docJSON(sourceJSON("A"), `{"name":"A","value":"v","account_uuid":"a","user_uuid":"u","account_url":"my.1password.com","vault_id":"","item_id":"i-A","field_id":"f"}`)), ErrBadJSON},
		{"var missing vault_id", b64(docJSON(sourceJSON("A"), `{"name":"A","value":"v","account_uuid":"a","user_uuid":"u","account_url":"my.1password.com","item_id":"i-A","field_id":"f"}`)), ErrBadJSON},
		{"trusted_sources missing", b64(`{"schema":2,"generated_at":"2026-09-14T17:02:11Z","vars":[]}`), ErrBadJSON},
		{"trusted_sources null", b64(`{"schema":2,"generated_at":"2026-09-14T17:02:11Z","trusted_sources":null,"vars":[]}`), ErrBadJSON},
		{"trusted_sources wrong type", b64(`{"schema":2,"generated_at":"2026-09-14T17:02:11Z","trusted_sources":{},"vars":[]}`), ErrBadJSON},
		{"null trusted source", b64(docJSON(`null`, ``)), ErrBadJSON},
		{"trusted source empty account_uuid", b64(docJSON(`{"account_uuid":"","user_uuid":"u","vault_id":"v","item_id":"i","field_id":"f","name":"A"}`, ``)), ErrBadJSON},
		{"trusted source empty user_uuid", b64(docJSON(`{"account_uuid":"a","user_uuid":"","vault_id":"v","item_id":"i","field_id":"f","name":"A"}`, ``)), ErrBadJSON},
		{"trusted source empty vault_id", b64(docJSON(`{"account_uuid":"a","user_uuid":"u","vault_id":"","item_id":"i","field_id":"f","name":"A"}`, ``)), ErrBadJSON},
		{"trusted source empty item_id", b64(docJSON(`{"account_uuid":"a","user_uuid":"u","vault_id":"v","item_id":"","field_id":"f","name":"A"}`, ``)), ErrBadJSON},
		{"trusted source empty field_id", b64(docJSON(`{"account_uuid":"a","user_uuid":"u","vault_id":"v","item_id":"i","field_id":"","name":"A"}`, ``)), ErrBadJSON},
		{"trusted source empty name", b64(docJSON(`{"account_uuid":"a","user_uuid":"u","vault_id":"v","item_id":"i","field_id":"f","name":""}`, ``)), ErrBadJSON},
		{"trusted source missing name", b64(docJSON(`{"account_uuid":"a","user_uuid":"u","vault_id":"v","item_id":"i","field_id":"f"}`, ``)), ErrBadJSON},
		{"repeated trusted source", b64(docJSON(sourceJSON("A")+`,`+sourceJSON("A"), ``)), ErrBadJSON},
		{"var with no trusted source", b64(docJSON(``, goodVarJSON("A"))), ErrBadJSON},
		{"var trusted under another name", b64(docJSON(sourceJSON("B"), goodVarJSON("A"))), ErrBadJSON},
		{"var trusted in another vault", b64(docJSON(strings.Replace(sourceJSON("A"), `"vault_id":"v"`, `"vault_id":"w"`, 1), goodVarJSON("A"))), ErrBadJSON},
		{"var trusted under another field", b64(docJSON(strings.Replace(sourceJSON("A"), `"field_id":"f"`, `"field_id":"g"`, 1), goodVarJSON("A"))), ErrBadJSON},
		{"var trusted under another user", b64(docJSON(strings.Replace(sourceJSON("A"), `"user_uuid":"u"`, `"user_uuid":"w"`, 1), goodVarJSON("A"))), ErrBadJSON},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Decode(tc.data)
			if !errors.Is(err, tc.want) {
				t.Errorf("Decode() error = %v, want errors.Is %v", err, tc.want)
			}
			// The tolerant reader is no laxer, except for schema 1.
			if _, err := DecodeAny(tc.data); tc.want != ErrLegacySchema && !errors.Is(err, tc.want) {
				t.Errorf("DecodeAny() error = %v, want errors.Is %v", err, tc.want)
			}
		})
	}
}

// goodVarJSON is one fully populated var entry named name. sourceJSON(name)
// is its trusted source.
func goodVarJSON(name string) string {
	return `{"name":"` + name + `","value":"v","account_uuid":"a","user_uuid":"u","account_url":"my.1password.com","vault_id":"v","item_id":"i-` + name + `","field_id":"f"}`
}

func sourceJSON(name string) string {
	return `{"account_uuid":"a","user_uuid":"u","vault_id":"v","item_id":"i-` + name + `","field_id":"f","name":"` + name + `"}`
}

// docJSON is a schema 2 document with the given raw array contents.
func docJSON(trusted, vars string) string {
	return `{"schema":2,"generated_at":"2026-09-14T17:02:11Z","trusted_sources":[` + trusted + `],"vars":[` + vars + `]}`
}

// varsJSON wraps var entries in a document that trusts the sources A, B,
// the bare item id "i" under A, and the marker name, so a test of one var
// rule does not trip the trust rule first.
func varsJSON(entries string) string {
	bare := `{"account_uuid":"a","user_uuid":"u","vault_id":"v","item_id":"i","field_id":"f","name":"A"}`
	return docJSON(sourceJSON("A")+`,`+sourceJSON("B")+`,`+sourceJSON(mark)+`,`+bare, entries)
}

// legacyVarJSON is a schema 1 var entry: no vault_id.
func legacyVarJSON(name string) string {
	return `{"name":"` + name + `","value":"v","account_uuid":"a","user_uuid":"u","account_url":"my.1password.com","item_id":"i-` + name + `","field_id":"f"}`
}

func legacyJSON(entries string) string {
	return `{"schema":1,"generated_at":"2026-09-14T17:02:11Z","vars":[` + entries + `]}`
}

// mark is content that must never appear in an error.
const mark = "MARKER-7f3a"

func TestDecodeAcceptsEmptyValueAndEmptyVars(t *testing.T) {
	// An empty value is rejected at sync, not here; a bundle carrying one is
	// still well-formed.
	for name, doc := range map[string]string{
		"empty vars":  varsJSON(``),
		"empty value": varsJSON(`{"name":"A","value":"","account_uuid":"a","user_uuid":"u","account_url":"my.1password.com","vault_id":"v","item_id":"i","field_id":"f"}`),
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
	for name, doc := range map[string]string{
		"missing value":      varsJSON(`{"name":"` + mark + `","account_uuid":"a","user_uuid":"u","account_url":"x","vault_id":"v","item_id":"i","field_id":"f"}`),
		"duplicate name":     varsJSON(goodVarJSON(mark) + `,` + goodVarJSON(mark)),
		"empty item_id":      varsJSON(`{"name":"` + mark + `","value":"` + mark + `","account_uuid":"a","user_uuid":"u","account_url":"x","vault_id":"v","item_id":"","field_id":"f"}`),
		"no trusted source":  docJSON(``, goodVarJSON(mark)),
		"repeated source":    docJSON(sourceJSON(mark)+`,`+sourceJSON(mark), ``),
		"empty source field": docJSON(`{"account_uuid":"`+mark+`","user_uuid":"`+mark+`","vault_id":"","item_id":"`+mark+`","field_id":"`+mark+`","name":"`+mark+`"}`, ``),
		"legacy to strict":   legacyJSON(legacyVarJSON(mark)),
		"legacy duplicate":   legacyJSON(legacyVarJSON(mark) + `,` + legacyVarJSON(mark)),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Decode(b64(doc))
			if err == nil {
				t.Fatal("want error")
			}
			if strings.Contains(err.Error(), mark) {
				t.Errorf("error text carries bundle content: %q", err.Error())
			}
			if _, err := DecodeAny(b64(doc)); err != nil && strings.Contains(err.Error(), mark) {
				t.Errorf("DecodeAny error text carries bundle content: %q", err.Error())
			}
		})
	}
}

func TestEncodeRefusesWhatDecodeRejects(t *testing.T) {
	good := mkVar("A", "v", "1")
	with := func(mut func(*Var)) Var { v := good; mut(&v); return v }
	one := func(v Var) Bundle { return mk(v) }
	src := good.Source()
	withSrc := func(mut func(*Source)) Bundle {
		s := src
		mut(&s)
		return Bundle{GeneratedAt: when, TrustedSources: []Source{s}}
	}
	legacy, err := DecodeAny(b64(legacyJSON(legacyVarJSON("A"))))
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]Bundle{
		"zero generated_at":     {TrustedSources: sources(good), Vars: []Var{good}},
		"empty name":            one(with(func(v *Var) { v.Name = "" })),
		"empty account_uuid":    one(with(func(v *Var) { v.AccountUUID = "" })),
		"empty user_uuid":       one(with(func(v *Var) { v.UserUUID = "" })),
		"empty account_url":     one(with(func(v *Var) { v.AccountURL = "" })),
		"empty vault_id":        one(with(func(v *Var) { v.VaultID = "" })),
		"empty item_id":         one(with(func(v *Var) { v.ItemID = "" })),
		"empty field_id":        one(with(func(v *Var) { v.FieldID = "" })),
		"duplicate names":       mk(good, mkVar("A", "other", "2")),
		"var not trusted":       {GeneratedAt: when, Vars: []Var{good}},
		"var trusted elsewhere": {GeneratedAt: when, TrustedSources: sources(mkVar("A", "other", "2")), Vars: []Var{good}},
		"repeated source":       {GeneratedAt: when, TrustedSources: []Source{src, src}},
		"source no account":     withSrc(func(s *Source) { s.AccountUUID = "" }),
		"source no user":        withSrc(func(s *Source) { s.UserUUID = "" }),
		"source no vault":       withSrc(func(s *Source) { s.VaultID = "" }),
		"source no item":        withSrc(func(s *Source) { s.ItemID = "" }),
		"source no field":       withSrc(func(s *Source) { s.FieldID = "" }),
		"source no name":        withSrc(func(s *Source) { s.Name = "" }),
		// A schema 1 bundle must be rebuilt, never rewritten as is.
		"legacy bundle":              legacy,
		"legacy vars, fresh sources": {GeneratedAt: when, TrustedSources: sources(legacy.Vars...), Vars: legacy.Vars},
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
	inputs := map[string][]byte{
		"malformed timestamp": b64(`{"schema":2,"generated_at":"` + mark + `","trusted_sources":[],"vars":[]}`),
		"syntax error":        b64(`{"schema":2,"generated_at":"2026-09-14T17:02:11Z","trusted_sources":[],"vars":[` + mark),
		"wrong type":          b64(`{"schema":"` + mark + `","vars":[]}`),
		"source wrong type":   b64(`{"schema":2,"generated_at":"2026-09-14T17:02:11Z","trusted_sources":["` + mark + `"],"vars":[]}`),
		"invalid utf8":        b64("{\"schema\":2,\"generated_at\":\"" + mark + "\xff\",\"vars\":[]}"),
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

func TestDiffIgnoresTheVaultALegacyVarNeverRecorded(t *testing.T) {
	legacy := mkVar("X", "same", "1")
	legacy.VaultID = ""
	if got := Diff(Bundle{Schema: LegacySchema, Vars: []Var{legacy}}, mk(mkVar("X", "same", "1"))); len(got) != 1 || got[0].Status != Unchanged {
		t.Errorf("Diff = %+v, want one unchanged row", got)
	}
	moved := mkVar("X", "same", "1")
	moved.VaultID = "vault-other"
	if got := Diff(mk(mkVar("X", "same", "1")), mk(moved)); len(got) != 1 || got[0].Status != Changed {
		t.Errorf("Diff = %+v, want one changed row for a vault move", got)
	}
}

func TestSourceID(t *testing.T) {
	s := Source{AccountUUID: "acct-1", UserUUID: "user-1", VaultID: "vault-1", ItemID: "item-1", FieldID: "field-1", Name: "GRAFANA_TOKEN"}
	// The preimage, written out by hand: the prefix, then each field behind
	// its 4-byte big-endian length.
	preimage := "envsec-source-v1\x00" +
		"\x00\x00\x00\x06acct-1" +
		"\x00\x00\x00\x06user-1" +
		"\x00\x00\x00\x07vault-1" +
		"\x00\x00\x00\x06item-1" +
		"\x00\x00\x00\x07field-1" +
		"\x00\x00\x00\x0dGRAFANA_TOKEN"
	sum := sha256.Sum256([]byte(preimage))
	byHand := "src_" + strings.ToLower(strings.TrimRight(base32.StdEncoding.EncodeToString(sum[:16]), "="))
	// The same vector from a separate implementation, recomputed 2026-11-13:
	//
	//	python3 -c 'import hashlib,base64,struct; f=["acct-1","user-1","vault-1","item-1","field-1","GRAFANA_TOKEN"]; p=b"envsec-source-v1\x00"+b"".join(struct.pack(">I",len(x))+x.encode() for x in f); print("src_"+base64.b32encode(hashlib.sha256(p).digest()[:16]).decode().lower().rstrip("="))'
	//
	// With f=[""]*6 the same command prints the zero Source id below.
	const fixed = "src_c653y6rf73ruo4vzrrtmfb2q4a"
	if got := s.ID(); got != byHand || got != fixed {
		t.Errorf("ID() = %q, by hand %q, fixed %q", got, byHand, fixed)
	}
	if got := (Source{}).ID(); got != "src_vpplfwb35hw75nwlkcyaouibdi" {
		t.Errorf("zero Source ID() = %q", got)
	}
	if got := mkVar("GRAFANA_TOKEN", "any value", "1").Source(); got != s || got.ID() != fixed {
		t.Errorf("Var.Source() = %+v", got)
	}
}

func TestSourceIDChangesWithEveryField(t *testing.T) {
	base := Source{"a", "u", "v", "i", "f", "N"}
	muts := map[string]func(*Source){
		"account_uuid": func(s *Source) { s.AccountUUID = "x" },
		"user_uuid":    func(s *Source) { s.UserUUID = "x" },
		"vault_id":     func(s *Source) { s.VaultID = "x" },
		"item_id":      func(s *Source) { s.ItemID = "x" },
		"field_id":     func(s *Source) { s.FieldID = "x" },
		"name":         func(s *Source) { s.Name = "x" },
	}
	seen := map[string]string{base.ID(): "base"}
	for name, mut := range muts {
		s := base
		mut(&s)
		id := s.ID()
		if prev, dup := seen[id]; dup {
			t.Errorf("changing %s gives the id of %s", name, prev)
		}
		seen[id] = name
	}
}

func TestSourceIDLengthPrefixSeparatesAdjacentFields(t *testing.T) {
	// The same bytes split differently between neighbours must not collide.
	pairs := map[string][2]Source{
		"account/user":   {{"ab", "c", "v", "i", "f", "N"}, {"a", "bc", "v", "i", "f", "N"}},
		"user/vault":     {{"a", "bc", "d", "i", "f", "N"}, {"a", "b", "cd", "i", "f", "N"}},
		"vault/item":     {{"a", "u", "vi", "j", "f", "N"}, {"a", "u", "v", "ij", "f", "N"}},
		"item/field":     {{"a", "u", "v", "if", "g", "N"}, {"a", "u", "v", "i", "fg", "N"}},
		"field/name":     {{"a", "u", "v", "i", "fN", "M"}, {"a", "u", "v", "i", "f", "NM"}},
		"swapped":        {{"a", "u", "v", "i", "f", "N"}, {"u", "a", "v", "i", "f", "N"}},
		"moved to empty": {{"a", "u", "v", "i", "f", ""}, {"a", "u", "v", "i", "", "f"}},
	}
	for name, p := range pairs {
		if p[0].ID() == p[1].ID() {
			t.Errorf("%s: %+v and %+v share an id", name, p[0], p[1])
		}
	}
	id := (Source{"a", "u", "v", "i", "f", "N"}).ID()
	if len(id) != 4+26 || id != strings.ToLower(id) || strings.Contains(id, "=") {
		t.Errorf("id shape: %q", id)
	}
}

func TestDecodeAnyAcceptsSchema2(t *testing.T) {
	in := mk(mkVar("A", "a", "1"))
	data, err := Encode(in)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeAny(data)
	if err != nil {
		t.Fatal(err)
	}
	if got.Legacy() || !reflect.DeepEqual(got, in) {
		t.Errorf("DecodeAny = %+v, want %+v", got, in)
	}
}

func TestDecodeAnyReadsSchema1AsUntrusted(t *testing.T) {
	// A hostile schema 1 document may claim trust and vaults. Neither
	// survives.
	doc := `{"schema":1,"generated_at":"2026-09-14T17:02:11Z","trusted_sources":[` + sourceJSON("A") + `],"vars":[` + goodVarJSON("A") + `,` + legacyVarJSON("B") + `]}`
	got, err := DecodeAny(b64(doc))
	if err != nil {
		t.Fatal(err)
	}
	if !got.Legacy() || got.Schema != LegacySchema {
		t.Errorf("Legacy() = %v, schema %d", got.Legacy(), got.Schema)
	}
	if got.TrustedSources == nil || len(got.TrustedSources) != 0 {
		t.Errorf("TrustedSources = %#v, want empty and non-nil", got.TrustedSources)
	}
	want := []Var{
		{Name: "A", Value: "v", AccountUUID: "a", UserUUID: "u", AccountURL: "my.1password.com", ItemID: "i-A", FieldID: "f"},
		{Name: "B", Value: "v", AccountUUID: "a", UserUUID: "u", AccountURL: "my.1password.com", ItemID: "i-B", FieldID: "f"},
	}
	if !reflect.DeepEqual(got.Vars, want) {
		t.Errorf("Vars = %+v, want %+v", got.Vars, want)
	}
	if !got.GeneratedAt.Equal(when) {
		t.Errorf("GeneratedAt = %v", got.GeneratedAt)
	}
	if got.Trusts(got.Vars[0].Source()) {
		t.Error("a legacy var is trusted")
	}
}

func TestDecodeAnyRejectsMalformedSchema1(t *testing.T) {
	for name, doc := range map[string]string{
		"no generated_at": `{"schema":1,"vars":[]}`,
		"no vars":         `{"schema":1,"generated_at":"2026-09-14T17:02:11Z"}`,
		"null vars":       `{"schema":1,"generated_at":"2026-09-14T17:02:11Z","vars":null}`,
		"null var":        legacyJSON(`null`),
		"no value":        legacyJSON(`{"name":"A","account_uuid":"a","user_uuid":"u","account_url":"x","item_id":"i","field_id":"f"}`),
		"empty name":      legacyJSON(`{"name":"","value":"v","account_uuid":"a","user_uuid":"u","account_url":"x","item_id":"i","field_id":"f"}`),
		"empty item_id":   legacyJSON(`{"name":"A","value":"v","account_uuid":"a","user_uuid":"u","account_url":"x","item_id":"","field_id":"f"}`),
		"duplicate names": legacyJSON(legacyVarJSON("A") + `,` + legacyVarJSON("A")),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeAny(b64(doc)); !errors.Is(err, ErrBadJSON) {
				t.Errorf("DecodeAny() error = %v, want ErrBadJSON", err)
			}
			if _, err := Decode(b64(doc)); !errors.Is(err, ErrLegacySchema) {
				t.Errorf("Decode() error = %v, want ErrLegacySchema", err)
			}
		})
	}
}

func TestTrustAndRevoke(t *testing.T) {
	a, b, c := mkVar("A", "a", "1"), mkVar("B", "b", "2"), mkVar("C", "c", "3")
	base := mk(a, b)
	if !base.Trusts(a.Source()) || base.Trusts(c.Source()) {
		t.Fatal("Trusts is wrong on the base bundle")
	}
	// Trust matches the whole tuple.
	for name, mut := range map[string]func(*Source){
		"name":  func(s *Source) { s.Name = "A2" },
		"vault": func(s *Source) { s.VaultID = "vault-x" },
		"field": func(s *Source) { s.FieldID = "field-x" },
		"item":  func(s *Source) { s.ItemID = "item-x" },
		"user":  func(s *Source) { s.UserUUID = "user-x" },
		"acct":  func(s *Source) { s.AccountUUID = "acct-x" },
	} {
		s := a.Source()
		mut(&s)
		if base.Trusts(s) {
			t.Errorf("a source with a different %s is trusted", name)
		}
	}

	more := base.Trust(c.Source(), a.Source(), c.Source())
	if want := sources(a, b, c); !reflect.DeepEqual(more.TrustedSources, want) {
		t.Errorf("Trust = %+v, want %+v", more.TrustedSources, want)
	}
	if len(more.Vars) != 2 {
		t.Errorf("Trust changed vars: %+v", more.Vars)
	}

	less := more.Revoke(a.Source(), mkVar("NOPE", "", "9").Source())
	if want := sources(b, c); !reflect.DeepEqual(less.TrustedSources, want) {
		t.Errorf("Revoke = %+v, want %+v", less.TrustedSources, want)
	}
	if !reflect.DeepEqual(less.Vars, []Var{b}) {
		t.Errorf("Revoke left vars %+v, want only B", less.Vars)
	}
	if _, err := Encode(less); err != nil {
		t.Errorf("a revoked bundle no longer encodes: %v", err)
	}

	// None of it touched the receiver.
	if !reflect.DeepEqual(base, mk(a, b)) || !reflect.DeepEqual(more.TrustedSources, sources(a, b, c)) {
		t.Errorf("Trust or Revoke mutated its receiver")
	}
	empty := Bundle{}.Trust()
	if empty.TrustedSources == nil || empty.Vars == nil {
		t.Error("Trust on the zero bundle left nil slices")
	}
}

func TestForgetAccount(t *testing.T) {
	keep := mkVar("KEEP", "k", "1")
	gone := mkVar("GONE", "g", "2")
	// Same account, another user, and a trusted source with no var.
	other := mkVar("OTHER", "o", "3")
	other.AccountUUID = gone.AccountUUID
	absent := mkVar("ABSENT", "", "4").Source()
	absent.AccountUUID = gone.AccountUUID
	b := mk(keep, gone, other).Trust(absent)

	got := b.ForgetAccount(gone.AccountUUID)
	if !reflect.DeepEqual(got.Vars, []Var{keep}) || !reflect.DeepEqual(got.TrustedSources, sources(keep)) {
		t.Errorf("ForgetAccount = %+v", got)
	}
	if len(b.Vars) != 3 || len(b.TrustedSources) != 4 {
		t.Error("ForgetAccount mutated its receiver")
	}
	if same := b.ForgetAccount("acct-unknown"); !reflect.DeepEqual(same, b) {
		t.Errorf("forgetting an unknown account changed the bundle: %+v", same)
	}
}

func TestIdentities(t *testing.T) {
	a := mkVar("A", "a", "1")
	a2 := mkVar("A2", "a", "1") // same identity as a, seen under another URL
	a2.AccountURL = "alt.1password.com"
	b := mkVar("B", "b", "2")
	b.AccountURL = "team.1password.com"
	absent := mkVar("ABSENT", "", "3").Source() // trusted, no var
	bundle := mk(b, a, a2).Trust(absent)

	want := []Identity{
		{AccountUUID: "acct-1", UserUUID: "user-1", AccountURL: "my.1password.com"},
		{AccountUUID: "acct-2", UserUUID: "user-2", AccountURL: "team.1password.com"},
		{AccountUUID: "acct-3", UserUUID: "user-3"},
	}
	if got := bundle.Identities(); !reflect.DeepEqual(got, want) {
		t.Errorf("Identities = %+v, want %+v", got, want)
	}

	// A legacy bundle has vars and no trusted sources.
	legacy, err := DecodeAny(b64(legacyJSON(legacyVarJSON("A"))))
	if err != nil {
		t.Fatal(err)
	}
	if got := legacy.Identities(); !reflect.DeepEqual(got, []Identity{{AccountUUID: "a", UserUUID: "u", AccountURL: "my.1password.com"}}) {
		t.Errorf("legacy Identities = %+v", got)
	}
	if got := (Bundle{}).Identities(); len(got) != 0 {
		t.Errorf("empty Identities = %+v", got)
	}
}

func TestEmptyVaultIDIsNamedInTheError(t *testing.T) {
	v := mkVar("A", "v", "1")
	trusted := sources(v)
	v.VaultID = ""
	_, err := Encode(Bundle{GeneratedAt: when, TrustedSources: trusted, Vars: []Var{v}})
	if err == nil || !strings.Contains(err.Error(), "vars[0] has an empty vault_id") {
		t.Errorf("Encode error = %v", err)
	}
	doc := docJSON(sourceJSON("A"), strings.Replace(goodVarJSON("A"), `"vault_id":"v"`, `"vault_id":""`, 1))
	_, err = Decode(b64(doc))
	if !errors.Is(err, ErrBadJSON) || !strings.Contains(err.Error(), "vars[0] has an empty vault_id") {
		t.Errorf("Decode error = %v", err)
	}
}
