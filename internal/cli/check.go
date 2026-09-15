package cli

import (
	"slices"
	"strings"

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

	// Exactly one row per var name. A name with any problem is reported as
	// conflict (if any problem is a conflict) or error, with every detail,
	// and is excluded from the comparison on both sides: there is no single
	// truth to compare against, so it must never also be ok, missing,
	// different, or stale.
	problems := aggregateProblems(res.Problems)
	resolved := make([]bundle.Var, 0, len(res.Vars))
	for _, v := range res.Vars {
		if _, bad := problems[v.Name]; !bad {
			resolved = append(resolved, v)
		}
	}
	stored := old
	stored.Vars = make([]bundle.Var, 0, len(old.Vars))
	for _, v := range old.Vars {
		if _, bad := problems[v.Name]; !bad {
			stored.Vars = append(stored.Vars, v)
		}
	}

	rows := make([]statusRow, 0, len(problems)+len(resolved)+len(stored.Vars))
	for name, p := range problems {
		rows = append(rows, statusRow{Var: name, Account: p.AccountURL, Status: p.Status, Detail: p.Detail})
	}
	for _, row := range bundle.Compare(stored, resolved) {
		rows = append(rows, statusRow{Var: row.Name, Account: row.AccountURL, Status: string(row.Status)})
	}
	slices.SortFunc(rows, func(a, b statusRow) int { return strings.Compare(a.Var, b.Var) })

	out := jsonl{rc.stdout}
	failures := 0
	for _, row := range rows {
		if row.Status != string(bundle.OK) {
			failures++
		}
		if err := out.Row(row); err != nil {
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

// aggregated is every problem for one var name folded into one row.
type aggregated struct {
	Status     string
	AccountURL string
	Detail     string
}

// aggregateProblems folds problems by var name. Status is conflict if any
// problem for the name is a conflict, else error. Detail joins conflict
// details first, then selection details, each in resolve order, with "; ".
// AccountURL is the selection failures' account when they all agree and the
// row is not a conflict; a conflict row has no single account.
func aggregateProblems(problems []problem) map[string]aggregated {
	conflicts := map[string][]string{}
	errs := map[string][]string{}
	accounts := map[string]string{}
	for _, p := range problems {
		if p.Conflict {
			conflicts[p.Var] = append(conflicts[p.Var], p.Detail)
			continue
		}
		errs[p.Var] = append(errs[p.Var], p.Detail)
		if prev, seen := accounts[p.Var]; !seen {
			accounts[p.Var] = p.AccountURL
		} else if prev != p.AccountURL {
			accounts[p.Var] = ""
		}
	}
	out := make(map[string]aggregated, len(conflicts)+len(errs))
	for name := range errs {
		out[name] = aggregated{Status: "error", AccountURL: accounts[name], Detail: strings.Join(errs[name], "; ")}
	}
	for name, details := range conflicts {
		out[name] = aggregated{Status: "conflict", Detail: strings.Join(append(details, errs[name]...), "; ")}
	}
	return out
}
