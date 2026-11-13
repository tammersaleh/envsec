// Package export holds the pure rules that turn 1Password fields into shell
// exports: the label pattern, the denylist, field selection, the split by
// trust, conflict detection, and zsh quoting. See SPEC.md "The 1Password contract" and
// "Hardening rules for env". It imports only stdlib and internal/bundle.
package export

import (
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/tammersaleh/envsec/internal/bundle"
)

// LabelPattern is the field label shape that opts a CONCEALED field in.
var LabelPattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

// deniedExact holds names that must never be exported: shell identity and
// loader variables, plus zsh special parameters that re-expand their value
// on every prompt or are read-only. BASH_ENV is expanded and sourced by every
// non-interactive bash. zsh expands the message part of MAILPATH when the
// watched file changes, and prompt-expands PROMPT_EOL_MARK. See SPEC.md "The
// 1Password contract".
var deniedExact = map[string]bool{
	"PATH": true, "HOME": true, "USER": true, "LOGNAME": true, "SHELL": true,
	"TMPDIR": true, "UID": true, "EUID": true, "IFS": true, "FPATH": true,
	"ZDOTDIR": true, "ENV": true, "SHLVL": true, "TERM": true, "LANG": true,
	"NODE_OPTIONS": true, "GIT_SSH_COMMAND": true,
	"PROMPT": true, "PS1": true, "PS2": true, "PS3": true, "PS4": true,
	"RPROMPT": true, "RPS1": true, "RPS2": true,
	"PROMPT2": true, "PROMPT3": true, "PROMPT4": true, "SPROMPT": true,
	"PPID": true, "LINENO": true, "RANDOM": true, "SECONDS": true,
	"COLUMNS": true, "LINES": true,
	"HISTSIZE": true, "SAVEHIST": true, "HISTFILE": true,
	"GID": true, "EGID": true, "USERNAME": true,
	"RPROMPT2": true, "KEYTIMEOUT": true, "FUNCNEST": true, "LISTMAX": true,
	"MAILCHECK": true, "OPTIND": true, "TRY_BLOCK_ERROR": true,
	"TRY_BLOCK_INTERRUPT": true, "ARGC": true, "HISTCMD": true, "TTYIDLE": true,
	"BASH_ENV": true, "MAILPATH": true, "PROMPT_EOL_MARK": true,
}

// deniedPrefixes: OP_ reconfigures the op child that sync runs; ZSH_ is the
// shell's own namespace. GIT_CONFIG_ (COUNT, KEY_<n>, VALUE_<n>, PARAMETERS)
// injects git config, and keys such as core.fsmonitor run a command.
var deniedPrefixes = []string{"LC_", "DYLD_", "LD_", "ENVSEC_", "OP_", "ZSH_", "GIT_CONFIG_"}

// Denied reports whether name may never be exported. Case-sensitive: labels
// that reach it already match LabelPattern.
func Denied(name string) bool {
	if deniedExact[name] {
		return true
	}
	for _, p := range deniedPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// Field is the subset of a 1Password item field that selection needs.
type Field struct {
	ID    string
	Type  string
	Label string
	Value string
}

// Item is the subset of a 1Password item that selection needs, plus the
// account it came from. VaultName, Title, and AccountURL are display only.
type Item struct {
	ID          string
	Title       string
	VaultID     string
	VaultName   string
	AccountUUID string
	UserUUID    string
	AccountURL  string
	Tags        []string
	Fields      []Field
}

// Origin is where a selected field came from: its source tuple, which is its
// identity, and the strings shown to the user, which are not. It holds no
// value. The display strings come from 1Password unescaped.
type Origin struct {
	Source     bundle.Source
	AccountURL string
	VaultName  string
	ItemTitle  string
}

// Candidate is one field that passed selection, with its value. Whether it
// is exported depends on trust, which Select knows nothing about.
type Candidate struct {
	Origin
	Value string
}

// Var is the bundle entry c would be stored as.
func (c Candidate) Var() bundle.Var {
	return bundle.Var{
		Name:        c.Source.Name,
		Value:       c.Value,
		AccountUUID: c.Source.AccountUUID,
		UserUUID:    c.Source.UserUUID,
		AccountURL:  c.AccountURL,
		VaultID:     c.Source.VaultID,
		ItemID:      c.Source.ItemID,
		FieldID:     c.Source.FieldID,
	}
}

// SelectError is one field that Select refused. Source.Name is the label.
// Reason is the human tail of the message ("label PATH is denylisted");
// Error renders it with the item. It never carries a value.
type SelectError struct {
	Origin
	Reason string
}

func (e *SelectError) Error() string {
	return fmt.Sprintf("item %q (%s): %s", e.ItemTitle, e.Source.ItemID, e.Reason)
}

// Select picks the candidates from one in-scope item: every CONCEALED field
// whose label matches LabelPattern. Fields with other types or labels are
// ignored. A denylisted label, an empty value, a value CheckValue refuses,
// or a source tuple with an empty part is an error. A label repeated within
// the item is not: both candidates are returned and DetectConflicts reports
// them. All errors are returned, in field order like the candidates. Both
// carry the full source tuple. Error text never includes a value.
func Select(item Item) ([]Candidate, []*SelectError) {
	var cands []Candidate
	var errs []*SelectError
	for _, f := range item.Fields {
		if f.Type != "CONCEALED" || !LabelPattern.MatchString(f.Label) {
			continue
		}
		origin := Origin{
			Source: bundle.Source{
				AccountUUID: item.AccountUUID,
				UserUUID:    item.UserUUID,
				VaultID:     item.VaultID,
				ItemID:      item.ID,
				FieldID:     f.ID,
				Name:        f.Label,
			},
			AccountURL: item.AccountURL,
			VaultName:  item.VaultName,
			ItemTitle:  item.Title,
		}
		if reason := refuse(origin.Source, f.Value); reason != "" {
			errs = append(errs, &SelectError{Origin: origin, Reason: reason})
			continue
		}
		cands = append(cands, Candidate{Origin: origin, Value: f.Value})
	}
	return cands, errs
}

// refuse returns why a field cannot be a candidate, or "".
func refuse(src bundle.Source, value string) string {
	if Denied(src.Name) {
		return "label " + src.Name + " is denylisted"
	}
	if value == "" {
		return src.Name + " is empty"
	}
	if err := CheckValue(value); err != nil {
		return src.Name + " " + err.Error()
	}
	// A source with an empty part can never be trusted or stored.
	for _, part := range []struct{ what, value string }{
		{"account UUID", src.AccountUUID},
		{"user UUID", src.UserUUID},
		{"vault ID", src.VaultID},
		{"item ID", src.ItemID},
		{"field ID", src.FieldID},
	} {
		if part.value == "" {
			return src.Name + " has no " + part.what
		}
	}
	return ""
}

// ConflictError is one var name yielded by more than one source. Sources are
// sorted by account URL, item ID, field ID, then identity.
type ConflictError struct {
	Name    string
	Sources []Origin
}

// Error names every source. When two sources share an item ID the field IDs
// are shown; when two distinct identities share an account URL the account
// and user UUIDs are shown, so the text always distinguishes the sources.
func (e *ConflictError) Error() string {
	type identity struct{ account, user string }
	items := map[string]bool{}
	urls := map[string]bool{}
	identities := map[identity]bool{}
	for _, o := range e.Sources {
		items[o.Source.ItemID] = true
		urls[o.AccountURL] = true
		identities[identity{o.Source.AccountUUID, o.Source.UserUUID}] = true
	}
	showField := len(items) < len(e.Sources)
	showIdentity := len(urls) < len(identities)
	parts := make([]string, len(e.Sources))
	for i, o := range e.Sources {
		p := "item " + o.Source.ItemID
		if showField {
			p += " field " + o.Source.FieldID
		}
		where := o.AccountURL
		if showIdentity {
			where += " account " + o.Source.AccountUUID + " user " + o.Source.UserUUID
		}
		parts[i] = p + " (" + where + ")"
	}
	return fmt.Sprintf("conflict: %s is defined by %s", e.Name, strings.Join(parts, " and "))
}

// conflictKey is conflict identity: (account, user, item, field). The vault
// and the account URL are not part of it.
type conflictKey struct{ account, user, item, field string }

// DetectConflicts returns one error per name that is yielded by more than
// one source, within one item, within one account, or across accounts. Two
// candidates with the same identity but different AccountURL are one source.
// Errors are sorted by name. Pass only the candidates that should conflict
// with each other: Split passes the trusted ones.
func DetectConflicts(cands []Candidate) []*ConflictError {
	byName := map[string][]Origin{}
	seen := map[string]map[conflictKey]bool{}
	for _, c := range cands {
		name := c.Source.Name
		k := conflictKey{c.Source.AccountUUID, c.Source.UserUUID, c.Source.ItemID, c.Source.FieldID}
		if seen[name] == nil {
			seen[name] = map[conflictKey]bool{}
		}
		if seen[name][k] {
			continue
		}
		seen[name][k] = true
		byName[name] = append(byName[name], c.Origin)
	}
	var errs []*ConflictError
	for _, name := range slices.Sorted(maps.Keys(byName)) {
		srcs := byName[name]
		if len(srcs) < 2 {
			continue
		}
		slices.SortFunc(srcs, func(a, b Origin) int {
			for _, c := range []int{
				strings.Compare(a.AccountURL, b.AccountURL),
				strings.Compare(a.Source.ItemID, b.Source.ItemID),
				strings.Compare(a.Source.FieldID, b.Source.FieldID),
				strings.Compare(a.Source.AccountUUID, b.Source.AccountUUID),
			} {
				if c != 0 {
					return c
				}
			}
			return strings.Compare(a.Source.UserUUID, b.Source.UserUUID)
		})
		errs = append(errs, &ConflictError{Name: name, Sources: srcs})
	}
	return errs
}

// Partition is a resolution judged against a set of trusted sources. See
// SPEC.md "Trust". Slices keep the order they were given in.
type Partition struct {
	// Trusted candidates become the bundle's vars, unless Fatal.
	Trusted []Candidate
	// Untrusted candidates are valid and could be trusted. Two of them may
	// share a name with each other or with a trusted candidate. That is not
	// a conflict.
	Untrusted []Candidate
	// TrustedProblems are validation failures on trusted sources. Fatal.
	TrustedProblems []*SelectError
	// UntrustedProblems are validation failures on sources that are not
	// trusted. They cannot be trusted and never block a write.
	UntrustedProblems []*SelectError
	// Conflicts are names yielded by more than one trusted candidate. Fatal.
	Conflicts []*ConflictError
}

// Fatal reports whether a trusted source failed, which aborts with no write.
func (p Partition) Fatal() bool {
	return len(p.TrustedProblems) > 0 || len(p.Conflicts) > 0
}

// Vars returns the trusted candidates as bundle vars. Names are unique only
// when Conflicts is empty.
func (p Partition) Vars() []bundle.Var {
	vars := make([]bundle.Var, len(p.Trusted))
	for i, c := range p.Trusted {
		vars[i] = c.Var()
	}
	return vars
}

// Split judges candidates and problems against trusted, matching on the
// whole source tuple. Conflicts are detected among the trusted candidates
// only. A source that appears more than once, as when one sign-in is listed
// under two account URLs, is kept once.
func Split(cands []Candidate, problems []*SelectError, trusted []bundle.Source) Partition {
	isTrusted := make(map[bundle.Source]bool, len(trusted))
	for _, s := range trusted {
		isTrusted[s] = true
	}
	var p Partition
	seen := map[bundle.Source]bool{}
	for _, c := range cands {
		if seen[c.Source] {
			continue
		}
		seen[c.Source] = true
		if isTrusted[c.Source] {
			p.Trusted = append(p.Trusted, c)
		} else {
			p.Untrusted = append(p.Untrusted, c)
		}
	}
	type failure struct {
		source bundle.Source
		reason string
	}
	failed := map[failure]bool{}
	for _, e := range problems {
		k := failure{e.Source, e.Reason}
		if failed[k] {
			continue
		}
		failed[k] = true
		if isTrusted[e.Source] {
			p.TrustedProblems = append(p.TrustedProblems, e)
		} else {
			p.UntrustedProblems = append(p.UntrustedProblems, e)
		}
	}
	p.Conflicts = DetectConflicts(p.Trusted)
	return p
}

// CheckValue is the one rule for what a value may hold, shared by Select
// (sync, check) and Quote (env): valid UTF-8, no C0 control byte (0x00-0x1F,
// including tab, CR, LF, NUL), no DEL (0x7F). Empty passes here; Select
// rejects it separately. The error is a predicate for the caller to prefix
// with its subject ("contains control byte 0x09", "is not valid UTF-8"). It
// names the first offending byte and never includes the value.
func CheckValue(value string) error {
	if !utf8.ValidString(value) {
		return errors.New("is not valid UTF-8")
	}
	for i := 0; i < len(value); i++ {
		if b := value[i]; b < 0x20 || b == 0x7f {
			return fmt.Errorf("contains control byte 0x%02x", b)
		}
	}
	return nil
}

// Quote single-quotes value for zsh; an embedded single quote becomes a
// closing quote, a backslash-escaped quote, and a reopening quote. Quote
// rejects whatever CheckValue rejects. Empty is allowed here; Select rejects
// it. The error never includes the value.
func Quote(value string) (string, error) {
	if err := CheckValue(value); err != nil {
		return "", fmt.Errorf("value %w", err)
	}
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'", nil
}

// ExportLine renders one line of `envsec env` output. The name must match
// LabelPattern; the value must pass Quote.
func ExportLine(name, value string) (string, error) {
	if !LabelPattern.MatchString(name) {
		return "", fmt.Errorf("invalid variable name %q", name)
	}
	q, err := Quote(value)
	if err != nil {
		return "", fmt.Errorf("%s: %w", name, err)
	}
	return Line(name, q), nil
}

// Line assembles an export line from a name that matches LabelPattern and a
// value already quoted by Quote. It validates nothing; use ExportLine unless
// the caller has already run both checks.
//
// The unset runs first so a parameter the caller's shell already typed
// (`typeset -i`, an array) cannot reinterpret the value: an integer parameter
// would evaluate `path[$(cmd)]` as arithmetic. The readonly guard comes
// first because unset is a special builtin: its failure aborts the rest of
// the enclosing eval, which is how the loader runs. A readonly target is
// skipped and the remaining lines still execute.
func Line(name, quoted string) string {
	return UnsetLine(name) + " && builtin export -- " + name + "=" + quoted
}

// UnsetLine renders the line that clears a rejected or no-longer-managed var,
// behind the same readonly guard as Line. `builtin` and `--` keep a shadowing
// function or an odd name from changing what runs.
func UnsetLine(name string) string {
	return readonlyGuard(name) + " && builtin unset -- " + name
}

// readonlyGuard is true unless the caller's shell has name as a readonly
// parameter of any type. ${(t)name} is empty for an unset parameter and
// contains "readonly" for scalar, integer, array, and association readonlys.
func readonlyGuard(name string) string {
	return "[[ ${(t)" + name + "} != *readonly* ]]"
}
