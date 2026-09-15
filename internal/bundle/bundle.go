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
// forced to Schema; a nil Vars encodes as an empty array.
func Encode(b Bundle) ([]byte, error) {
	b.Schema = Schema
	b.Vars = slices.Clone(b.Vars)
	if b.Vars == nil {
		b.Vars = []Var{}
	}
	slices.SortFunc(b.Vars, func(a, c Var) int { return strings.Compare(a.Name, c.Name) })
	raw, err := json.Marshal(b)
	if err != nil {
		return nil, fmt.Errorf("encode bundle: %w", err)
	}
	return []byte(base64.StdEncoding.EncodeToString(raw)), nil
}

// Decode parses a keychain value written by Encode.
func Decode(data []byte) (Bundle, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return Bundle{}, fmt.Errorf("%w: %v", ErrBadBase64, err)
	}
	var b Bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return Bundle{}, fmt.Errorf("%w: %v", ErrBadJSON, err)
	}
	if b.Schema != Schema {
		return Bundle{}, fmt.Errorf("%w: got %d, want %d", ErrUnknownSchema, b.Schema, Schema)
	}
	if b.Vars == nil {
		b.Vars = []Var{}
	}
	return b, nil
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
