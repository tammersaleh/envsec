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

var deniedExact = map[string]bool{
	"PATH": true, "HOME": true, "USER": true, "LOGNAME": true, "SHELL": true,
	"TMPDIR": true, "UID": true, "EUID": true, "IFS": true, "FPATH": true,
	"ZDOTDIR": true, "ENV": true, "SHLVL": true, "TERM": true, "LANG": true,
	"NODE_OPTIONS": true, "GIT_SSH_COMMAND": true,
}

var deniedPrefixes = []string{"LC_", "DYLD_", "LD_", "ENVSEC_"}

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

// Select picks the exportable vars from one in-scope item: every CONCEALED
// field whose label matches LabelPattern. Fields with other types or labels
// are ignored. A denylisted label, a label repeated within the item, an
// empty value, or a value containing CR or LF is an error. All errors are
// returned; vars are in field order. Error text never includes a value.
func Select(item Item) ([]bundle.Var, []error) {
	var vars []bundle.Var
	var errs []error
	seen := map[string]bool{}
	where := fmt.Sprintf("item %q (%s)", item.Title, item.ID)
	for _, f := range item.Fields {
		if f.Type != "CONCEALED" || !LabelPattern.MatchString(f.Label) {
			continue
		}
		switch {
		case Denied(f.Label):
			errs = append(errs, fmt.Errorf("%s: label %s is denylisted", where, f.Label))
			continue
		case seen[f.Label]:
			errs = append(errs, fmt.Errorf("%s: label %s appears more than once", where, f.Label))
			continue
		case f.Value == "":
			errs = append(errs, fmt.Errorf("%s: %s is empty", where, f.Label))
			continue
		case strings.ContainsAny(f.Value, "\r\n"):
			errs = append(errs, fmt.Errorf("%s: %s contains a newline", where, f.Label))
			continue
		}
		seen[f.Label] = true
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

// DetectConflicts returns one error per var name that is yielded by more than
// one item, within or across accounts. Each error names every source item and
// account. Errors are sorted by var name; sources by account URL then item ID.
func DetectConflicts(vars []bundle.Var) []error {
	type source struct{ url, item string }
	byName := map[string][]source{}
	for _, v := range vars {
		s := source{v.AccountURL, v.ItemID}
		if !slices.Contains(byName[v.Name], s) {
			byName[v.Name] = append(byName[v.Name], s)
		}
	}
	var errs []error
	for _, name := range slices.Sorted(maps.Keys(byName)) {
		srcs := byName[name]
		if len(srcs) < 2 {
			continue
		}
		slices.SortFunc(srcs, func(a, b source) int {
			if c := strings.Compare(a.url, b.url); c != 0 {
				return c
			}
			return strings.Compare(a.item, b.item)
		})
		parts := make([]string, len(srcs))
		for i, s := range srcs {
			parts[i] = fmt.Sprintf("item %s (%s)", s.item, s.url)
		}
		errs = append(errs, fmt.Errorf("conflict: %s is defined by %s", name, strings.Join(parts, " and ")))
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
	return "builtin export -- " + name + "=" + q, nil
}

// UnsetLine renders the line that clears a rejected or no-longer-managed var.
func UnsetLine(name string) string {
	return "unset " + name
}
