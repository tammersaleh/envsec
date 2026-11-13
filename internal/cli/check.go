package cli

import (
	"github.com/tammersaleh/envsec/internal/bundle"
)

// CheckCmd compares 1Password against the keychain bundle without writing.
// See SPEC.md "envsec check". Prints no values and no hashes.
type CheckCmd struct{}

func (CheckCmd) Run(rc *runContext) error {
	res, err := resolve(rc, "check")
	if err != nil {
		return err
	}
	// A missing bundle is not a failure here. Like a schema 1 bundle, it
	// trusts nothing, so every valid source is untrusted.
	old, err := readBundleOrEmpty(rc)
	if err != nil {
		return err
	}

	// Exactly one row per var name. A name with a conflict, an error, or an
	// untrusted source gets that row and no other: there is no single truth
	// to compare, so it is never also ok, missing, different, or stale.
	// Only the trusted sources are compared with the bundle.
	p := res.split(old.TrustedSources)
	rows := mergeRows(problemRows(p, nil), bundle.Compare(old, p.Vars()))
	return emit(rc, "check", rows, nil)
}
