// Package bundle defines the keychain bundle: the single JSON document envsec
// stores base64-encoded in the login keychain. See SPEC.md "The keychain
// contract".
package bundle

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

// Schema is the bundle schema version this build reads and writes.
const Schema = 1

// Var is one exported variable and its 1Password provenance.
type Var struct {
	Name        string `json:"name"`
	Value       string `json:"value"`
	AccountUUID string `json:"account_uuid"`
	UserUUID    string `json:"user_uuid"`
	AccountURL  string `json:"account_url"`
	ItemID      string `json:"item_id"`
	FieldID     string `json:"field_id"`
}

// Bundle is the decoded keychain value.
type Bundle struct {
	Schema      int       `json:"schema"`
	GeneratedAt time.Time `json:"generated_at"`
	Vars        []Var     `json:"vars"`
}

// Decode error sentinels. Callers use errors.Is to map them to exit 4.
var (
	ErrBadBase64     = errors.New("bundle is not valid base64")
	ErrBadJSON       = errors.New("bundle is not valid JSON")
	ErrUnknownSchema = errors.New("bundle schema is not supported")
)

// Encode renders b as the keychain value: JSON, then standard base64.
// Vars are sorted by name so equal bundles encode identically. Schema is
// forced to Schema; a nil Vars encodes as an empty array. Encode refuses any
// bundle Decode would reject (zero GeneratedAt, a var with an empty field
// other than Value, duplicate names) so a buggy writer cannot poison the
// keychain. The error never carries a value.
func Encode(b Bundle) ([]byte, error) {
	b.Schema = Schema
	b.Vars = slices.Clone(b.Vars)
	if b.Vars == nil {
		b.Vars = []Var{}
	}
	if b.GeneratedAt.IsZero() {
		return nil, errors.New("encode bundle: generated_at is zero")
	}
	if err := validateVars(b.Vars); err != nil {
		return nil, fmt.Errorf("encode bundle: %w", err)
	}
	slices.SortFunc(b.Vars, func(a, c Var) int { return strings.Compare(a.Name, c.Name) })
	raw, err := json.Marshal(b)
	if err != nil {
		return nil, fmt.Errorf("encode bundle: %w", err)
	}
	return []byte(base64.StdEncoding.EncodeToString(raw)), nil
}

// wire is the decoded JSON before validation. Pointers distinguish absent
// and null from the zero value.
type wire struct {
	Schema      int         `json:"schema"`
	GeneratedAt *string     `json:"generated_at"`
	Vars        *[]*wireVar `json:"vars"`
}

// wireVar is one vars entry before validation. Value is a pointer so a
// missing or null value is told apart from an empty string.
type wireVar struct {
	Name        string  `json:"name"`
	Value       *string `json:"value"`
	AccountUUID string  `json:"account_uuid"`
	UserUUID    string  `json:"user_uuid"`
	AccountURL  string  `json:"account_url"`
	ItemID      string  `json:"item_id"`
	FieldID     string  `json:"field_id"`
}

// Decode parses a keychain value written by Encode. Every structural
// problem is ErrBadJSON: invalid UTF-8 anywhere in the decoded document, a
// missing, null, malformed, or zero generated_at, a missing or null vars, a
// null vars entry, a var with a missing or null value, a var with an empty
// name, account_uuid, user_uuid, account_url, item_id, or field_id, or two
// vars with the same name. Error text wraps the sentinel with a fixed phrase
// and never quotes the underlying json or time error, because those echo
// bundle content.
func Decode(data []byte) (Bundle, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return Bundle{}, fmt.Errorf("%w: %v", ErrBadBase64, err)
	}
	if !utf8.Valid(raw) {
		return Bundle{}, fmt.Errorf("%w: invalid UTF-8", ErrBadJSON)
	}
	var w wire
	if err := json.Unmarshal(raw, &w); err != nil {
		return Bundle{}, fmt.Errorf("%w: unmarshal failed", ErrBadJSON)
	}
	if w.Schema != Schema {
		return Bundle{}, fmt.Errorf("%w: got %d, want %d", ErrUnknownSchema, w.Schema, Schema)
	}
	if w.GeneratedAt == nil {
		return Bundle{}, fmt.Errorf("%w: missing generated_at", ErrBadJSON)
	}
	at, err := time.Parse(time.RFC3339Nano, *w.GeneratedAt)
	if err != nil || at.IsZero() {
		return Bundle{}, fmt.Errorf("%w: generated_at is not a valid timestamp", ErrBadJSON)
	}
	if w.Vars == nil {
		return Bundle{}, fmt.Errorf("%w: missing vars", ErrBadJSON)
	}
	vars := make([]Var, 0, len(*w.Vars))
	for i, wv := range *w.Vars {
		if wv == nil {
			return Bundle{}, fmt.Errorf("%w: vars[%d] is null", ErrBadJSON, i)
		}
		if wv.Value == nil {
			return Bundle{}, fmt.Errorf("%w: vars[%d] has no value", ErrBadJSON, i)
		}
		vars = append(vars, Var{
			Name: wv.Name, Value: *wv.Value,
			AccountUUID: wv.AccountUUID, UserUUID: wv.UserUUID, AccountURL: wv.AccountURL,
			ItemID: wv.ItemID, FieldID: wv.FieldID,
		})
	}
	if err := validateVars(vars); err != nil {
		return Bundle{}, fmt.Errorf("%w: %v", ErrBadJSON, err)
	}
	return Bundle{Schema: w.Schema, GeneratedAt: at, Vars: vars}, nil
}

// validateVars enforces the per-var rules shared by Encode and Decode: every
// field but Value is nonempty and names are unique. Errors name the index,
// never the content, because a name or value may be anything.
func validateVars(vars []Var) error {
	seen := make(map[string]int, len(vars))
	for i, v := range vars {
		for _, f := range []struct{ name, value string }{
			{"name", v.Name},
			{"account_uuid", v.AccountUUID},
			{"user_uuid", v.UserUUID},
			{"account_url", v.AccountURL},
			{"item_id", v.ItemID},
			{"field_id", v.FieldID},
		} {
			if f.value == "" {
				return fmt.Errorf("vars[%d] has an empty %s", i, f.name)
			}
		}
		if j, dup := seen[v.Name]; dup {
			return fmt.Errorf("vars[%d] repeats the name of vars[%d]", i, j)
		}
		seen[v.Name] = i
	}
	return nil
}

// Status is a per-var comparison result.
type Status string

// Diff statuses (sync output).
const (
	Added     Status = "added"
	Unchanged Status = "unchanged"
	Changed   Status = "changed"
	Removed   Status = "removed"
)

// Compare statuses (check output).
const (
	OK        Status = "ok"
	Missing   Status = "missing"
	Different Status = "different"
	Stale     Status = "stale"
)

// Row is one line of sync or check output. No value is carried.
type Row struct {
	Name       string
	AccountURL string
	Status     Status
}

// Diff compares the previous bundle to the one about to be written. Vars match
// by name. Changed means the value or any provenance field differs. Removed
// rows carry the old account URL. Result is sorted by name.
func Diff(old, cur Bundle) []Row {
	return rows(old.Vars, cur.Vars, Added, Unchanged, Changed, Removed)
}

// Compare checks the stored bundle against vars freshly resolved from
// 1Password. Missing is in resolved but not the bundle; stale is in the bundle
// but not resolved; different is any value or provenance difference. Resolved
// must already be conflict-free (unique names); on duplicates the first wins.
// Result is sorted by name.
func Compare(b Bundle, resolved []Var) []Row {
	return rows(b.Vars, resolved, Missing, OK, Different, Stale)
}

func rows(before, after []Var, onlyAfter, same, differs, onlyBefore Status) []Row {
	prev := index(before)
	cur := index(after)
	out := make([]Row, 0, len(prev)+len(cur))
	for name, v := range cur {
		st := onlyAfter
		if p, ok := prev[name]; ok {
			st = same
			if p != v {
				st = differs
			}
		}
		out = append(out, Row{Name: name, AccountURL: v.AccountURL, Status: st})
	}
	for name, p := range prev {
		if _, ok := cur[name]; !ok {
			out = append(out, Row{Name: name, AccountURL: p.AccountURL, Status: onlyBefore})
		}
	}
	slices.SortFunc(out, func(a, c Row) int { return strings.Compare(a.Name, c.Name) })
	return out
}

func index(vars []Var) map[string]Var {
	m := make(map[string]Var, len(vars))
	for _, v := range vars {
		if _, dup := m[v.Name]; !dup {
			m[v.Name] = v
		}
	}
	return m
}
