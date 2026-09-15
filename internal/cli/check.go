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
	// A missing bundle is not a failure here: every var is simply missing.
	old, err := readBundleOrEmpty(rc)
	if err != nil {
		return err
	}

	out := jsonl{rc.stdout}
	failures := 0
	conflicted := map[string]bool{}
	for _, p := range res.Problems {
		status := "error"
		if p.Conflict {
			status = "conflict"
			conflicted[p.Var] = true
		}
		if err := out.Row(statusRow{Var: p.Var, Status: status, Detail: p.Detail}); err != nil {
			return err
		}
		failures++
	}

	// Compare wants unique names; a conflicted var has no single truth to
	// compare against, so it is reported only as a conflict.
	resolved := make([]bundle.Var, 0, len(res.Vars))
	for _, v := range res.Vars {
		if !conflicted[v.Name] {
			resolved = append(resolved, v)
		}
	}
	for _, row := range bundle.Compare(old, resolved) {
		if row.Status != bundle.OK {
			failures++
		}
		if err := out.Row(statusRow{Var: row.Name, Account: row.AccountURL, Status: string(row.Status)}); err != nil {
			return err
		}
	}
	if err := out.Meta(Meta{ErrorCount: &failures}); err != nil {
		return err
	}
	if failures > 0 {
		return &ExitError{Code: ExitFailure, Err: "check_failed", Silent: true}
	}
	return nil
}
