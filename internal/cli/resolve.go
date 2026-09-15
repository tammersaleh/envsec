package cli

import (
	"errors"
	"fmt"

	"github.com/tammersaleh/envsec/internal/bundle"
	"github.com/tammersaleh/envsec/internal/export"
	"github.com/tammersaleh/envsec/internal/onepass"
)

// problem is a non-fatal resolve failure: a field that could not be selected
// or a var yielded by more than one source. Var is the label or var name.
// AccountURL is the item's account for a selection failure and empty for a
// conflict, which may span accounts.
type problem struct {
	Var        string
	AccountURL string
	Conflict   bool
	Detail     string
}

// resolution is everything sync and check learn from 1Password.
type resolution struct {
	Vars     []bundle.Var
	Accounts []onepass.Account
	Problems []problem
	// InScopeItems counts items that were fetched and still carry the tag,
	// whether or not they yield vars. Zero means the tag search found
	// nothing anywhere; sync refuses to write an empty bundle on that
	// without --prune-all.
	InScopeItems int
}

// resolve lists every account, fetches every item tagged rc.globals.Tag, and
// selects its vars. It is the read side shared by sync and check and never
// touches the keychain.
//
// An *onepass.AuthError anywhere is fatal with exit 2; any other op failure
// is fatal with exit 1 naming the account and item. Selection and conflict
// failures are returned as Problems alongside every var that did resolve;
// the caller decides what they mean. cmd names the caller in fatal details.
func resolve(rc *runContext, cmd string) (resolution, error) {
	var res resolution
	tag := rc.globals.Tag
	op := rc.deps.OnePass

	accounts, err := op.Accounts(rc.ctx)
	if err != nil {
		return res, opFatal(cmd, err, onepass.Account{}, "list accounts")
	}
	if len(accounts) == 0 {
		// The real client already reports this; the check here keeps the
		// contract when the client is swapped.
		return res, opFatal(cmd, &onepass.AuthError{Detail: "no 1Password accounts are signed in"}, onepass.Account{}, "list accounts")
	}
	res.Accounts = accounts

	for _, acct := range accounts {
		summaries, err := op.ListTagged(rc.ctx, acct, tag)
		if err != nil {
			return res, opFatal(cmd, err, acct, fmt.Sprintf("list items tagged %q", tag))
		}
		for _, summary := range summaries {
			item, err := op.GetItem(rc.ctx, acct, summary.ID)
			if err != nil {
				return res, opFatal(cmd, err, acct, "get item "+summary.ID)
			}
			// The tag may have been removed between list and get.
			if !onepass.HasTag(item, tag) {
				continue
			}
			res.InScopeItems++
			vars, errs := export.Select(toExportItem(item, acct))
			res.Vars = append(res.Vars, vars...)
			for _, e := range errs {
				res.Problems = append(res.Problems, problem{Var: e.Label, AccountURL: acct.URL, Detail: e.Error()})
			}
		}
	}

	for _, e := range export.DetectConflicts(res.Vars) {
		res.Problems = append(res.Problems, problem{Var: e.Name, Conflict: true, Detail: e.Error()})
	}
	return res, nil
}

// toExportItem copies the fields selection needs and stamps the account.
func toExportItem(item onepass.Item, acct onepass.Account) export.Item {
	fields := make([]export.Field, len(item.Fields))
	for i, f := range item.Fields {
		fields[i] = export.Field{ID: f.ID, Type: f.Type, Label: f.Label, Value: f.Value}
	}
	return export.Item{
		ID:          item.ID,
		Title:       item.Title,
		AccountUUID: acct.AccountUUID,
		UserUUID:    acct.UserUUID,
		AccountURL:  acct.URL,
		Tags:        item.Tags,
		Fields:      fields,
	}
}

// opFatal maps an op failure to the fatal *ExitError for cmd. what says which
// call failed; acct is the zero value for account-less calls.
func opFatal(cmd string, err error, acct onepass.Account, what string) error {
	var ae *onepass.AuthError
	if errors.As(err, &ae) {
		if ae.Account.URL == "" {
			ae.Account = acct
		}
		who := "1Password"
		hint := "op signin"
		if ae.Account.URL != "" {
			who = "account " + ae.Account.URL
			hint = "op signin --account " + ae.Account.URL
		}
		why := ""
		if ae.Detail != "" {
			why = ": " + ae.Detail
		}
		return &ExitError{
			Code:   ExitOnePassAuth,
			Err:    "onepassword_unauthorized",
			Detail: fmt.Sprintf("%s aborted: %s could not be authorized%s; keychain cache unchanged; unlock 1Password and rerun", cmd, who, why),
			Hint:   hint,
		}
	}
	where := what
	if acct.URL != "" {
		where = "account " + acct.URL + ": " + what
	}
	return &ExitError{
		Code:   ExitFailure,
		Err:    "onepassword_failed",
		Detail: fmt.Sprintf("%s aborted: %s: %v; keychain cache unchanged", cmd, where, err),
		Hint:   "fix the 1Password error and rerun envsec " + cmd,
	}
}
