// Package trustpicker shows a checkbox list of sources on the terminal and
// returns the ones the user confirmed. It is the only package that imports
// huh.
package trustpicker

import (
	"errors"
	"fmt"
	"slices"
)

// ErrCancelled means the user left the picker without confirming, or the
// terminal failed. The caller writes nothing. Match it with errors.Is. It is
// never returned for a confirm, including a confirm with nothing checked.
var ErrCancelled = errors.New("trust picker cancelled")

// Option is one line in the picker. ID is opaque to this package and must be
// unique within one Pick.
type Option struct {
	ID      string
	Var     string
	Account string
	Vault   string
	Item    string
	Checked bool
}

// Picker asks the user which options to trust.
type Picker interface {
	// Available reports whether Pick can talk to a person.
	Available() bool
	// Pick returns the IDs of the options checked at confirm, in the order
	// of opts. A confirm with nothing checked returns an empty non-nil
	// slice and a nil error. A cancel returns nil and an error matching
	// ErrCancelled.
	Pick(opts []Option) ([]string, error)
}

// CheckSelection refuses a selection that checks two options with the same
// Var. checked holds indexes into opts.
func CheckSelection(opts []Option, checked []int) error {
	sorted := slices.Clone(checked)
	slices.Sort(sorted)
	seen := make(map[string]bool, len(sorted))
	for _, i := range sorted {
		if i < 0 || i >= len(opts) {
			continue
		}
		v := opts[i].Var
		if seen[v] {
			return fmt.Errorf("%s is checked twice, keep one", Escape(v))
		}
		seen[v] = true
	}
	return nil
}

// checkOptions catches caller bugs that would make a selection ambiguous.
func checkOptions(opts []Option) error {
	seen := make(map[string]bool, len(opts))
	for i, o := range opts {
		if o.ID == "" {
			return fmt.Errorf("trustpicker: option %d has no id", i)
		}
		if seen[o.ID] {
			return fmt.Errorf("trustpicker: option id %q is repeated", o.ID)
		}
		seen[o.ID] = true
	}
	return nil
}
