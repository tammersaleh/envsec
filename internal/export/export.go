// Package export holds the pure rules that turn 1Password fields into shell
// exports: the label pattern, the denylist, field selection, conflict
// detection, and zsh quoting. See SPEC.md "The 1Password contract" and
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
// on every prompt or are read-only. See SPEC.md "The 1Password contract".
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
}

// deniedPrefixes: OP_ reconfigures the op child that sync runs; ZSH_ is the
// shell's own namespace.
var deniedPrefixes = []string{"LC_", "DYLD_", "LD_", "ENVSEC_", "OP_", "ZSH_"}

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
// account it came from.
type Item struct {
	ID          string
	Title       string
	AccountUUID string
	UserUUID    string
	AccountURL  string
	Tags        []string
	Fields      []Field
}

// SelectError is one field that Select refused. Reason is the human tail of
// the message ("label PATH is denylisted"); Error renders it with the item.
// It never carries a value.
type SelectError struct {
	ItemID    string
	ItemTitle string
	Label     string
	Reason    string
}

func (e *SelectError) Error() string {
	return fmt.Sprintf("item %q (%s): %s", e.ItemTitle, e.ItemID, e.Reason)
}

// Select picks the exportable vars from one in-scope item: every CONCEALED
// field whose label matches LabelPattern. Fields with other types or labels
// are ignored. A denylisted label, an empty value, or a value containing CR
// or LF is an error. A label repeated within the item is not: both vars are
// returned and DetectConflicts reports them. All errors are returned; vars
// are in field order. Error text never includes a value.
func Select(item Item) ([]bundle.Var, []*SelectError) {
	var vars []bundle.Var
	var errs []*SelectError
	fail := func(label, reason string) {
		errs = append(errs, &SelectError{ItemID: item.ID, ItemTitle: item.Title, Label: label, Reason: reason})
	}
	for _, f := range item.Fields {
		if f.Type != "CONCEALED" || !LabelPattern.MatchString(f.Label) {
			continue
		}
		switch {
		case Denied(f.Label):
			fail(f.Label, "label "+f.Label+" is denylisted")
			continue
		case f.Value == "":
			fail(f.Label, f.Label+" is empty")
			continue
		case strings.ContainsAny(f.Value, "\r\n"):
			fail(f.Label, f.Label+" contains a newline")
			continue
		}
		vars = append(vars, bundle.Var{
			Name:        f.Label,
			Value:       f.Value,
			AccountUUID: item.AccountUUID,
			UserUUID:    item.UserUUID,
			AccountURL:  item.AccountURL,
			ItemID:      item.ID,
			FieldID:     f.ID,
		})
	}
	return vars, errs
}

// Source is one field that yields a conflicting var. Identity is
// (AccountUUID, UserUUID, ItemID, FieldID); AccountURL is for display only
// and never part of the key.
type Source struct {
	AccountURL  string
	AccountUUID string
	UserUUID    string
	ItemID      string
	FieldID     string
}

// ConflictError is one var name yielded by more than one source. Sources are
// sorted by account URL, item ID, field ID, then identity.
type ConflictError struct {
	Name    string
	Sources []Source
}

// Error names every source. When two sources share an item ID the field IDs
// are shown; when two distinct identities share an account URL the account
// and user UUIDs are shown, so the text always distinguishes the sources.
func (e *ConflictError) Error() string {
	type identity struct{ account, user string }
	items := map[string]bool{}
	urls := map[string]bool{}
	identities := map[identity]bool{}
	for _, s := range e.Sources {
		items[s.ItemID] = true
		urls[s.AccountURL] = true
		identities[identity{s.AccountUUID, s.UserUUID}] = true
	}
	showField := len(items) < len(e.Sources)
	showIdentity := len(urls) < len(identities)
	parts := make([]string, len(e.Sources))
	for i, s := range e.Sources {
		p := "item " + s.ItemID
		if showField {
			p += " field " + s.FieldID
		}
		where := s.AccountURL
		if showIdentity {
			where += " account " + s.AccountUUID + " user " + s.UserUUID
		}
		parts[i] = p + " (" + where + ")"
	}
	return fmt.Sprintf("conflict: %s is defined by %s", e.Name, strings.Join(parts, " and "))
}

// DetectConflicts returns one error per var name that is yielded by more than
// one source, within one item, within one account, or across accounts. Two
// vars with the same identity but different AccountURL are one source.
// Errors are sorted by var name.
func DetectConflicts(vars []bundle.Var) []*ConflictError {
	type key struct{ account, user, item, field string }
	byName := map[string][]Source{}
	seen := map[string]map[key]bool{}
	for _, v := range vars {
		k := key{v.AccountUUID, v.UserUUID, v.ItemID, v.FieldID}
		if seen[v.Name] == nil {
			seen[v.Name] = map[key]bool{}
		}
		if seen[v.Name][k] {
			continue
		}
		seen[v.Name][k] = true
		byName[v.Name] = append(byName[v.Name], Source{
			AccountURL: v.AccountURL, AccountUUID: v.AccountUUID, UserUUID: v.UserUUID, ItemID: v.ItemID, FieldID: v.FieldID,
		})
	}
	var errs []*ConflictError
	for _, name := range slices.Sorted(maps.Keys(byName)) {
		srcs := byName[name]
		if len(srcs) < 2 {
			continue
		}
		slices.SortFunc(srcs, func(a, b Source) int {
			for _, c := range []int{
				strings.Compare(a.AccountURL, b.AccountURL),
				strings.Compare(a.ItemID, b.ItemID),
				strings.Compare(a.FieldID, b.FieldID),
				strings.Compare(a.AccountUUID, b.AccountUUID),
			} {
				if c != 0 {
					return c
				}
			}
			return strings.Compare(a.UserUUID, b.UserUUID)
		})
		errs = append(errs, &ConflictError{Name: name, Sources: srcs})
	}
	return errs
}

// Quote single-quotes value for zsh; an embedded single quote becomes a
// closing quote, a backslash-escaped quote, and a reopening quote. Quote
// rejects invalid UTF-8 and every C0 control byte (0x00-0x1F, including tab,
// CR, LF, NUL) and DEL (0x7F). Empty is allowed here; Select rejects it.
// The error never includes the value.
func Quote(value string) (string, error) {
	if !utf8.ValidString(value) {
		return "", errors.New("value is not valid UTF-8")
	}
	for i := 0; i < len(value); i++ {
		if b := value[i]; b < 0x20 || b == 0x7f {
			return "", fmt.Errorf("value contains control byte 0x%02x", b)
		}
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
