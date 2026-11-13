package cli

import (
	"errors"
	"fmt"

	"github.com/tammersaleh/envsec/internal/bundle"
	"github.com/tammersaleh/envsec/internal/export"
	"github.com/tammersaleh/envsec/internal/onepass"
)

// resolution is everything sync, trust, and check learn from 1Password,
// before any trust decision. Every candidate and every problem carries its
// full source tuple and display strings.
type resolution struct {
	// Candidates are the fields that passed selection, in resolve order.
	// Names may repeat: conflicts are judged later, among trusted sources.
	Candidates []export.Candidate
	// Problems are the fields selection refused, in resolve order.
	Problems []*export.SelectError
	Accounts []onepass.Account
	// InScopeItems counts items that were fetched and still carry the tag,
	// whether or not they yield vars. Zero means the tag search found
	// nothing anywhere; sync refuses to write an empty bundle on that
	// without --prune-all.
	InScopeItems int
}

// resolve lists every account, fetches every item tagged rc.globals.Tag, and
// selects its fields. It is the read side shared by sync, trust, and check.
// It never touches the keychain and knows nothing about trust: call split
// with the bundle's trusted sources to judge the result.
//
// An *onepass.AuthError anywhere is fatal with exit 2; any other op failure
// is fatal with exit 1 naming the account and item. Selection failures are
// returned as Problems alongside every candidate that did resolve. cmd names
// the caller in fatal details.
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
			cands, errs := export.Select(toExportItem(item, acct))
			res.Candidates = append(res.Candidates, cands...)
			res.Problems = append(res.Problems, errs...)
		}
	}
	return res, nil
}

// split judges the resolution against trusted, the bundle's trusted
// sources: trusted candidates, untrusted candidates, problems on trusted
// sources (fatal), problems on untrusted sources (error rows), and conflicts
// among the trusted candidates only (fatal). See export.Split.
func (r resolution) split(trusted []bundle.Source) export.Partition {
	return export.Split(r.Candidates, r.Problems, trusted)
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
		VaultID:     item.Vault.ID,
		VaultName:   item.Vault.Name,
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
