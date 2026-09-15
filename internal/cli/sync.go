package cli

import (
	"errors"
	"fmt"
	"slices"

	"github.com/tammersaleh/envsec/internal/bundle"
	"github.com/tammersaleh/envsec/internal/keychain"
)

// SyncCmd copies tagged 1Password fields into the keychain bundle. See
// SPEC.md "envsec sync" and "Hardening rules for sync". Everything resolves
// before the single keychain write; any failure leaves the bundle untouched.
type SyncCmd struct {
	ForgetAccount []string `name:"forget-account" help:"Account UUID whose vars may be dropped because it left op account list. Repeatable." placeholder:"UUID"`
	PruneAll      bool     `help:"Allow writing an empty bundle when 1Password yields no vars."`
}

// statusRow is one line of sync or check output. Never carries a value.
type statusRow struct {
	Var     string `json:"var"`
	Account string `json:"account,omitempty"`
	Status  string `json:"status"`
	Detail  string `json:"detail,omitempty"`
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
	out := jsonl{rc.stdout}
	if len(res.Problems) > 0 {
		for _, p := range res.Problems {
			if err := out.Row(statusRow{Var: p.Var, Status: "error", Detail: p.Detail}); err != nil {
				return err
			}
		}
		n := len(res.Problems)
		if err := out.Meta(Meta{ErrorCount: &n}); err != nil {
			return err
		}
		return &ExitError{Code: ExitFailure, Err: "sync_failed", Silent: true}
	}

	old, err := readBundleOrEmpty(rc)
	if err != nil {
		return err
	}

	if err := c.guardVanishedAccounts(old, res); err != nil {
		return err
	}
	if len(res.Vars) == 0 && len(old.Vars) > 0 && !c.PruneAll {
		return &ExitError{
			Code:   ExitFailure,
			Err:    "prune_refused",
			Detail: fmt.Sprintf("1Password yielded no vars but the keychain bundle holds %d; refusing to empty it", len(old.Vars)),
			Hint:   "envsec sync --prune-all",
		}
	}

	cur := bundle.Bundle{Schema: bundle.Schema, GeneratedAt: rc.deps.Now().UTC(), Vars: res.Vars}
	raw, err := bundle.Encode(cur)
	if err != nil {
		return err
	}
	if err := rc.deps.Keychain.Write(rc.ctx, raw); err != nil {
		e := asExit(err)
		if e.Code != ExitKeychain {
			e = &ExitError{Code: ExitKeychain, Err: "keychain_unavailable", Detail: err.Error()}
		}
		e.Hint = "unlock the login keychain and rerun envsec sync"
		return e
	}

	for _, row := range bundle.Diff(old, cur) {
		if err := out.Row(statusRow{Var: row.Name, Account: row.AccountURL, Status: string(row.Status)}); err != nil {
			return err
		}
	}
	zero := 0
	return out.Meta(Meta{ErrorCount: &zero})
}

// guardVanishedAccounts refuses to drop an account that is in the old bundle
// but no longer in op account list unless --forget-account names it.
func (c SyncCmd) guardVanishedAccounts(old bundle.Bundle, res resolution) error {
	present := map[string]bool{}
	for _, a := range res.Accounts {
		present[a.AccountUUID] = true
	}
	seen := map[string]bool{}
	for _, v := range old.Vars {
		if present[v.AccountUUID] || seen[v.AccountUUID] || slices.Contains(c.ForgetAccount, v.AccountUUID) {
			continue
		}
		seen[v.AccountUUID] = true
		return &ExitError{
			Code:   ExitFailure,
			Err:    "account_missing",
			Detail: fmt.Sprintf("account %s (%s) is in the keychain bundle but not in op account list", v.AccountUUID, v.AccountURL),
			Hint:   "envsec sync --forget-account " + v.AccountUUID,
		}
	}
	return nil
}

// readBundleOrEmpty is readBundle for the writers: a missing item is the
// empty bundle (first run), every other failure is fatal exit 4.
func readBundleOrEmpty(rc *runContext) (bundle.Bundle, error) {
	raw, err := rc.deps.Keychain.Read(rc.ctx)
	if errors.Is(err, keychain.ErrNotFound) {
		return bundle.Bundle{Schema: bundle.Schema, Vars: []bundle.Var{}}, nil
	}
	if err != nil {
		return bundle.Bundle{}, asExit(err)
	}
	b, err := bundle.Decode(raw)
	if err != nil {
		return bundle.Bundle{}, &ExitError{Code: ExitKeychain, Err: "bundle_invalid", Detail: err.Error(),
			Hint: "security delete-generic-password -s envsec -a bundle ~/Library/Keychains/login.keychain-db, then envsec sync"}
	}
	return b, nil
}
