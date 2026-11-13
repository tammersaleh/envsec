// Package bundle defines the keychain bundle: the single JSON document envsec
// stores base64-encoded in the login keychain. See SPEC.md "The keychain
// contract".
package bundle

import (
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

// Schema is the bundle schema version this build writes. LegacySchema
// predates source trust: no trusted_sources and no vault_id.
const (
	Schema       = 2
	LegacySchema = 1
)

// sourceIDPrefix domain-separates the source id hash.
const sourceIDPrefix = "envsec-source-v1\x00"

// Source identifies one selected 1Password field. Name is the field label.
// A change to any part is a different source. See SPEC.md "Trust".
type Source struct {
	AccountUUID string `json:"account_uuid"`
	UserUUID    string `json:"user_uuid"`
	VaultID     string `json:"vault_id"`
	ItemID      string `json:"item_id"`
	FieldID     string `json:"field_id"`
	Name        string `json:"name"`
}

// fields lists the six parts in hash order, with their JSON names.
func (s Source) fields() [6]struct{ name, value string } {
	return [6]struct{ name, value string }{
		{"account_uuid", s.AccountUUID},
		{"user_uuid", s.UserUUID},
		{"vault_id", s.VaultID},
		{"item_id", s.ItemID},
		{"field_id", s.FieldID},
		{"name", s.Name},
	}
}

// ID is the id shown to the user: "src_" plus lowercase unpadded base32 of
// the first 16 bytes of SHA-256 over sourceIDPrefix and the six fields, each
// prefixed with its byte length as a 4-byte big-endian integer. It is
// derived on demand and never stored.
func (s Source) ID() string {
	h := sha256.New()
	h.Write([]byte(sourceIDPrefix))
	var n [4]byte
	for _, f := range s.fields() {
		binary.BigEndian.PutUint32(n[:], uint32(len(f.value)))
		h.Write(n[:])
		h.Write([]byte(f.value))
	}
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	return "src_" + strings.ToLower(enc.EncodeToString(h.Sum(nil)[:16]))
}

// compareSources orders sources by name, then by the remaining parts.
func compareSources(a, b Source) int {
	for _, c := range []int{
		strings.Compare(a.Name, b.Name),
		strings.Compare(a.AccountUUID, b.AccountUUID),
		strings.Compare(a.UserUUID, b.UserUUID),
		strings.Compare(a.VaultID, b.VaultID),
		strings.Compare(a.ItemID, b.ItemID),
	} {
		if c != 0 {
			return c
		}
	}
	return strings.Compare(a.FieldID, b.FieldID)
}

// Var is one exported variable and its 1Password provenance. VaultID is
// empty only in a var read from a schema 1 bundle.
type Var struct {
	Name        string `json:"name"`
	Value       string `json:"value"`
	AccountUUID string `json:"account_uuid"`
	UserUUID    string `json:"user_uuid"`
	AccountURL  string `json:"account_url"`
	VaultID     string `json:"vault_id"`
	ItemID      string `json:"item_id"`
	FieldID     string `json:"field_id"`
}

// Source is the source tuple v was read from.
func (v Var) Source() Source {
	return Source{
		AccountUUID: v.AccountUUID, UserUUID: v.UserUUID, VaultID: v.VaultID,
		ItemID: v.ItemID, FieldID: v.FieldID, Name: v.Name,
	}
}

// Bundle is the decoded keychain value. In a schema 2 bundle every var
// matches a trusted source. A trusted source need not have a var.
type Bundle struct {
	Schema         int       `json:"schema"`
	GeneratedAt    time.Time `json:"generated_at"`
	TrustedSources []Source  `json:"trusted_sources"`
	Vars           []Var     `json:"vars"`
}

// Decode error sentinels. Callers use errors.Is to map them to exit 4.
// ErrLegacySchema is a schema 1 bundle given to Decode: it holds no trust
// decisions, so env and list must not use it.
var (
	ErrBadBase64     = errors.New("bundle is not valid base64")
	ErrBadJSON       = errors.New("bundle is not valid JSON")
	ErrUnknownSchema = errors.New("bundle schema is not supported")
	ErrLegacySchema  = errors.New("bundle predates source trust")
)

// Encode renders b as the keychain value: JSON, then standard base64. It
// writes schema 2 only. Vars are sorted by name and trusted sources by name
// then identity, so equal bundles encode identically. Nil slices encode as
// empty arrays. Encode refuses any bundle Decode would reject, so a buggy
// writer cannot poison the keychain. That includes vars carried over from a
// schema 1 bundle, which have no vault id and no trusted source. The error
// never carries a value.
func Encode(b Bundle) ([]byte, error) {
	b.Schema = Schema
	b.Vars = slices.Clone(b.Vars)
	if b.Vars == nil {
		b.Vars = []Var{}
	}
	b.TrustedSources = slices.Clone(b.TrustedSources)
	if b.TrustedSources == nil {
		b.TrustedSources = []Source{}
	}
	if b.GeneratedAt.IsZero() {
		return nil, errors.New("encode bundle: generated_at is zero")
	}
	if err := validate(b.TrustedSources, b.Vars); err != nil {
		return nil, fmt.Errorf("encode bundle: %w", err)
	}
	slices.SortFunc(b.Vars, func(a, c Var) int { return strings.Compare(a.Name, c.Name) })
	slices.SortFunc(b.TrustedSources, compareSources)
	raw, err := json.Marshal(b)
	if err != nil {
		return nil, fmt.Errorf("encode bundle: %w", err)
	}
	return []byte(base64.StdEncoding.EncodeToString(raw)), nil
}

// wire is the decoded JSON before validation. Pointers distinguish absent
// and null from the zero value.
type wire struct {
	Schema         int         `json:"schema"`
	GeneratedAt    *string     `json:"generated_at"`
	TrustedSources *[]*Source  `json:"trusted_sources"`
	Vars           *[]*wireVar `json:"vars"`
}

// wireVar is one vars entry before validation. Value is a pointer so a
// missing or null value is told apart from an empty string.
type wireVar struct {
	Name        string  `json:"name"`
	Value       *string `json:"value"`
	AccountUUID string  `json:"account_uuid"`
	UserUUID    string  `json:"user_uuid"`
	AccountURL  string  `json:"account_url"`
	VaultID     string  `json:"vault_id"`
	ItemID      string  `json:"item_id"`
	FieldID     string  `json:"field_id"`
}

// Decode is the strict reader for env and list. It accepts schema 2 only. A
// schema 1 document is ErrLegacySchema whatever else it holds. Every
// structural problem is ErrBadJSON: invalid UTF-8 anywhere in the decoded
// document, a missing, null, malformed, or zero generated_at, a missing or
// null vars, a null vars entry, a var with a missing or null value, a var
// with an empty name, account_uuid, user_uuid, account_url, vault_id,
// item_id, or field_id, two vars with the same name, a missing or null
// trusted_sources, a null trusted source, a trusted source with an empty
// field, a repeated trusted source, or a var with no matching trusted
// source. Error text wraps the sentinel with a fixed phrase and never quotes
// the underlying json or time error, because those echo bundle content.
func Decode(data []byte) (Bundle, error) {
	return decode(data, false)
}

// DecodeAny is the reader for sync, trust, and check. It accepts what Decode
// accepts, plus a structurally valid schema 1 bundle, which it returns with
// Schema set to LegacySchema, an empty TrustedSources, and vars whose
// VaultID is empty. Legacy reports that case. Legacy vars are untrusted
// input: use them for diffing and the vanished-account guard, never copy
// them into a new bundle. Encode refuses them.
func DecodeAny(data []byte) (Bundle, error) {
	return decode(data, true)
}

// Legacy reports whether b was read from a schema 1 bundle.
func (b Bundle) Legacy() bool { return b.Schema == LegacySchema }

func decode(data []byte, allowLegacy bool) (Bundle, error) {
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
	switch {
	case w.Schema == Schema:
	case w.Schema == LegacySchema && allowLegacy:
	case w.Schema == LegacySchema:
		return Bundle{}, fmt.Errorf("%w: schema %d", ErrLegacySchema, LegacySchema)
	default:
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
			VaultID: wv.VaultID, ItemID: wv.ItemID, FieldID: wv.FieldID,
		})
	}
	if w.Schema == LegacySchema {
		// Whatever a schema 1 document says about vaults or trust is
		// dropped: it was written before either existed.
		for i := range vars {
			vars[i].VaultID = ""
		}
		if err := validateVars(vars, false); err != nil {
			return Bundle{}, fmt.Errorf("%w: %v", ErrBadJSON, err)
		}
		return Bundle{Schema: LegacySchema, GeneratedAt: at, TrustedSources: []Source{}, Vars: vars}, nil
	}
	if w.TrustedSources == nil {
		return Bundle{}, fmt.Errorf("%w: missing trusted_sources", ErrBadJSON)
	}
	trusted := make([]Source, 0, len(*w.TrustedSources))
	for i, ws := range *w.TrustedSources {
		if ws == nil {
			return Bundle{}, fmt.Errorf("%w: trusted_sources[%d] is null", ErrBadJSON, i)
		}
		trusted = append(trusted, *ws)
	}
	if err := validate(trusted, vars); err != nil {
		return Bundle{}, fmt.Errorf("%w: %v", ErrBadJSON, err)
	}
	return Bundle{Schema: Schema, GeneratedAt: at, TrustedSources: trusted, Vars: vars}, nil
}

// validate enforces the schema 2 rules shared by Encode and Decode. Errors
// name the index, never the content, because any string may be anything.
func validate(trusted []Source, vars []Var) error {
	seen := make(map[Source]int, len(trusted))
	for i, s := range trusted {
		for _, f := range s.fields() {
			if f.value == "" {
				return fmt.Errorf("trusted_sources[%d] has an empty %s", i, f.name)
			}
		}
		if j, dup := seen[s]; dup {
			return fmt.Errorf("trusted_sources[%d] repeats trusted_sources[%d]", i, j)
		}
		seen[s] = i
	}
	if err := validateVars(vars, true); err != nil {
		return err
	}
	for i, v := range vars {
		if _, ok := seen[v.Source()]; !ok {
			return fmt.Errorf("vars[%d] has no matching trusted source", i)
		}
	}
	return nil
}

// validateVars enforces the per-var rules: every field but Value is nonempty
// and names are unique. A schema 1 var has no vault id, so needVault is
// false there.
func validateVars(vars []Var, needVault bool) error {
	seen := make(map[string]int, len(vars))
	for i, v := range vars {
		fields := []struct{ name, value string }{
			{"name", v.Name},
			{"account_uuid", v.AccountUUID},
			{"user_uuid", v.UserUUID},
			{"account_url", v.AccountURL},
			{"item_id", v.ItemID},
			{"field_id", v.FieldID},
		}
		if needVault {
			fields = append(fields, struct{ name, value string }{"vault_id", v.VaultID})
		}
		for _, f := range fields {
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

// Trusts reports whether s is in b's trusted sources, by exact tuple.
func (b Bundle) Trusts(s Source) bool {
	return slices.Contains(b.TrustedSources, s)
}

// Trust returns a copy of b that also trusts srcs. A source already trusted
// is not added twice. Vars are unchanged.
func (b Bundle) Trust(srcs ...Source) Bundle {
	out := b.clone()
	for _, s := range srcs {
		if !slices.Contains(out.TrustedSources, s) {
			out.TrustedSources = append(out.TrustedSources, s)
		}
	}
	return out
}

// Revoke returns a copy of b without srcs in its trusted sources and without
// the vars read from them. A source that is not trusted is ignored.
func (b Bundle) Revoke(srcs ...Source) Bundle {
	return b.without(func(s Source) bool { return slices.Contains(srcs, s) })
}

// ForgetAccount returns a copy of b without any trusted source or var under
// accountUUID, whatever the user UUID. It is what --forget-account applies.
func (b Bundle) ForgetAccount(accountUUID string) Bundle {
	return b.without(func(s Source) bool { return s.AccountUUID == accountUUID })
}

// without drops every trusted source and var whose source matches drop.
func (b Bundle) without(drop func(Source) bool) Bundle {
	out := b.clone()
	out.TrustedSources = slices.DeleteFunc(out.TrustedSources, drop)
	out.Vars = slices.DeleteFunc(out.Vars, func(v Var) bool { return drop(v.Source()) })
	return out
}

// clone copies b with its own non-nil slices.
func (b Bundle) clone() Bundle {
	b.TrustedSources = append([]Source{}, b.TrustedSources...)
	b.Vars = append([]Var{}, b.Vars...)
	return b
}

// Identity is one 1Password sign-in the bundle refers to. AccountURL is for
// display and is empty when only a trusted source names the identity.
type Identity struct {
	AccountUUID string
	UserUUID    string
	AccountURL  string
}

// Identities returns every (account UUID, user UUID) pair named by a var or
// a trusted source, sorted. The vanished-account guard checks each against
// op account list.
func (b Bundle) Identities() []Identity {
	type key struct{ account, user string }
	urls := map[key]string{}
	for _, s := range b.TrustedSources {
		urls[key{s.AccountUUID, s.UserUUID}] = ""
	}
	for _, v := range b.Vars {
		k := key{v.AccountUUID, v.UserUUID}
		if urls[k] == "" {
			urls[k] = v.AccountURL
		}
	}
	out := make([]Identity, 0, len(urls))
	for k, url := range urls {
		out = append(out, Identity{AccountUUID: k.account, UserUUID: k.user, AccountURL: url})
	}
	slices.SortFunc(out, func(a, c Identity) int {
		if d := strings.Compare(a.AccountUUID, c.AccountUUID); d != 0 {
			return d
		}
		return strings.Compare(a.UserUUID, c.UserUUID)
	})
	return out
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
// by name. Changed means the value or any provenance field differs. A var
// from a schema 1 bundle has no vault id, and that alone is not a change.
// Removed rows carry the old account URL. Result is sorted by name.
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
			// A schema 1 var never recorded its vault.
			if p.VaultID == "" {
				p.VaultID = v.VaultID
			}
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
