package cli

import (
	"errors"
	"fmt"
	"slices"

	"github.com/tammersaleh/envsec/internal/bundle"
	"github.com/tammersaleh/envsec/internal/keychain"
)

// SyncCmd copies trusted, tagged 1Password fields into the keychain bundle.
// See SPEC.md "envsec sync", "Trust", and "Hardening rules for sync".
// Everything resolves before the single keychain write. Any failure on a
// trusted source leaves the bundle untouched.
type SyncCmd struct {
	ForgetAccount []string `name:"forget-account" help:"Account UUID whose vars and trusted sources may be dropped because it left op account list. Forgets every user under it. Repeatable." placeholder:"UUID"`
	PruneAll      bool     `help:"Allow writing a bundle with no vars when no item carries the tag in any account. Trusted sources are kept."`
}

func (c SyncCmd) Run(rc *runContext) error {
	release, err := acquireLock()
	if err != nil {
		return err
	}
	defer release()

	res, err := resolve(rc, "sync")
	if err != nil {
		return err
	}
	old, err := readBundleOrEmpty(rc)
	if err != nil {
		return err
	}
	// The guards come before the picker, so a refusal never follows a
	// choice the user already made.
	if err := guard(rc, old, res, c.ForgetAccount, c.PruneAll); err != nil {
		return err
	}

	// Stored trust is kept whether or not 1Password still has the source.
	// Only --forget-account drops any.
	kept := old
	for _, uuid := range c.ForgetAccount {
		kept = kept.ForgetAccount(uuid)
	}
	forgot := len(kept.TrustedSources) != len(old.TrustedSources) || len(kept.Vars) != len(old.Vars)
	trusted := kept.TrustedSources

	// Nothing trusted (no bundle, a schema 1 bundle, an empty list, or every
	// trusted account forgotten) and something to trust: ask, if there is
	// someone to ask. With nothing to trust there is nothing to ask, and
	// sync goes on to write a bundle with no vars.
	if valid := res.validOrigins(); len(trusted) == 0 && len(valid) > 0 {
		if rc.deps.Picker.Available() {
			trusted, err = pick(rc, valid, func(bundle.Source) bool { return false })
			if err != nil {
				return err
			}
		}
		// No terminal, or a confirm with nothing checked: write nothing
		// and say what is waiting. A forgotten account is a change of its
		// own and is still written, or the rerun would need the flag again.
		if len(trusted) == 0 && !forgot {
			p := res.split(nil)
			return emit(rc, "sync", problemRows(p, nil), untrustedNames(p, nil))
		}
	}

	return change{cmd: "sync", old: old, res: res, trusted: trusted}.apply(rc)
}

// guard runs the checks sync and trust share before either changes anything.
//
// An identity (account UUID plus user UUID) named by the old bundle, in a
// var or a trusted source, that is no longer in op account list is refused
// unless forget names its account UUID, which forgets every user under it.
//
// Zero in-scope items anywhere usually means the wrong tag or account, so
// writing a bundle with no vars needs pruneAll always, first run included.
func guard(rc *runContext, old bundle.Bundle, res resolution, forget []string, pruneAll bool) error {
	type identity struct{ account, user string }
	present := map[identity]bool{}
	for _, a := range res.Accounts {
		present[identity{a.AccountUUID, a.UserUUID}] = true
	}
	for _, id := range old.Identities() {
		if present[identity{id.AccountUUID, id.UserUUID}] || slices.Contains(forget, id.AccountUUID) {
			continue
		}
		// An identity named only by a trusted source has no URL on record.
		who := fmt.Sprintf("account %s user %s", id.AccountUUID, id.UserUUID)
		if id.AccountURL != "" {
			who += " (" + id.AccountURL + ")"
		}
		return &ExitError{
			Code:   ExitFailure,
			Err:    "account_missing",
			Detail: who + " is in the keychain bundle but not in op account list",
			Hint:   "envsec sync --forget-account " + id.AccountUUID,
		}
	}
	if res.InScopeItems == 0 && !pruneAll {
		return &ExitError{
			Code:   ExitFailure,
			Err:    "prune_refused",
			Detail: fmt.Sprintf("no items tagged %q in any account; the keychain bundle holds %d var(s); refusing to write an empty bundle", rc.globals.Tag, len(old.Vars)),
			Hint:   "envsec sync --prune-all",
		}
	}
	return nil
}

// readBundleOrEmpty is readBundle for sync, trust, and check: a missing item
// is the empty bundle (first run), every other failure is fatal exit 4. A
// schema 1 bundle is returned with Legacy() true and no trusted sources. Its
// vars are for diffing and the vanished-account guard only.
func readBundleOrEmpty(rc *runContext) (bundle.Bundle, error) {
	raw, err := rc.deps.Keychain.Read(rc.ctx)
	if errors.Is(err, keychain.ErrNotFound) {
		return bundle.Bundle{Schema: bundle.Schema, TrustedSources: []bundle.Source{}, Vars: []bundle.Var{}}, nil
	}
	if err != nil {
		return bundle.Bundle{}, asExit(err)
	}
	b, err := bundle.DecodeAny(raw)
	if err != nil {
		return bundle.Bundle{}, &ExitError{Code: ExitKeychain, Err: "bundle_invalid", Detail: err.Error(),
			Hint: "security delete-generic-password -s envsec -a bundle ~/Library/Keychains/login.keychain-db, then envsec sync"}
	}
	return b, nil
}
