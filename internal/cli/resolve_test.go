package cli

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/tammersaleh/envsec/internal/bundle"
	"github.com/tammersaleh/envsec/internal/export"
	"github.com/tammersaleh/envsec/internal/onepass"
)

func newRC(op onepass.Client, tag string) *runContext {
	return &runContext{ctx: context.Background(), globals: Globals{Tag: tag}, deps: Deps{OnePass: op}}
}

// labels renders candidates as "NAME@item" so a failure never prints a value.
func labels(cs []export.Candidate) []string {
	var out []string
	for _, c := range cs {
		out = append(out, c.Source.Name+"@"+c.Source.ItemID)
	}
	return out
}

func TestResolveWalksEveryAccountBeforeReturning(t *testing.T) {
	op := twoAccountOp()
	op.Items[acct2.AccountUUID] = append(op.Items[acct2.AccountUUID], opItem("item-b", "B", secret("B", "b")))
	res, err := resolve(newRC(op, "shell-env"), "sync")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Accounts) != 2 || res.InScopeItems != 3 {
		t.Fatalf("accounts=%d items=%d", len(res.Accounts), res.InScopeItems)
	}
	// TOKEN is in both accounts. Resolve reports both and judges neither.
	if got, want := labels(res.Candidates), []string{"TOKEN@item-token", "TOKEN@item-token2", "B@item-b"}; !slices.Equal(got, want) {
		t.Fatalf("candidates = %v, want %v", got, want)
	}
	if len(res.Problems) != 0 {
		t.Fatalf("problems = %+v", res.Problems)
	}
	wantCalls := []onepass.Call{
		{Method: "Accounts"},
		{Method: "ListTagged", AccountUUID: "ACCT", Arg: "shell-env"},
		{Method: "GetItem", AccountUUID: "ACCT", Arg: "item-token"},
		{Method: "ListTagged", AccountUUID: "ACCT2", Arg: "shell-env"},
		{Method: "GetItem", AccountUUID: "ACCT2", Arg: "item-token2"},
		{Method: "GetItem", AccountUUID: "ACCT2", Arg: "item-b"},
	}
	if len(op.Calls) != len(wantCalls) {
		t.Fatalf("calls = %+v", op.Calls)
	}
	for i := range wantCalls {
		if op.Calls[i] != wantCalls[i] {
			t.Fatalf("call %d = %+v, want %+v", i, op.Calls[i], wantCalls[i])
		}
	}
}

func TestResolveCarriesFullProvenance(t *testing.T) {
	// One valid field and one refused field, in the second account. Both
	// carry the six-part tuple and the display strings. Account identity
	// comes from the account, the rest from the item.
	it := onepass.Item{
		ID: "item-x", Title: "Deploy keys", Vault: onepass.Vault{ID: "vault-x", Name: "Shared"},
		Tags:   []string{"shell-env"},
		Fields: []onepass.Field{secret("GOOD", "g"), secret("PATH", "p")},
	}
	op := &onepass.Fake{AccountList: []onepass.Account{acct1, acct2}, Items: map[string][]onepass.Item{acct2.AccountUUID: {it}}}
	res, err := resolve(newRC(op, "shell-env"), "sync")
	if err != nil {
		t.Fatal(err)
	}
	origin := func(name string) export.Origin {
		return export.Origin{
			Source: bundle.Source{
				AccountUUID: "ACCT2", UserUUID: "USER2", VaultID: "vault-x",
				ItemID: "item-x", FieldID: "field-" + strings.ToLower(name), Name: name,
			},
			AccountURL: "other.1password.com", VaultName: "Shared", ItemTitle: "Deploy keys",
		}
	}
	if len(res.Candidates) != 1 || res.Candidates[0].Origin != origin("GOOD") || res.Candidates[0].Value != marker+"-g" {
		t.Fatalf("candidates = %v", labels(res.Candidates))
	}
	if len(res.Problems) != 1 || res.Problems[0].Origin != origin("PATH") {
		t.Fatalf("problems = %+v", res.Problems)
	}
	if got, want := res.Problems[0].Error(), `item "Deploy keys" (item-x): label PATH is denylisted`; got != want {
		t.Fatalf("problem = %q, want %q", got, want)
	}
	if res.InScopeItems != 1 {
		t.Fatalf("an item that yields an error is still in scope: %d", res.InScopeItems)
	}
}

func TestResolveSplit(t *testing.T) {
	// ACCT has TOKEN and a denylisted PATH. ACCT2 has another TOKEN and an
	// empty EMPTY.
	op := twoAccountOp()
	op.Items[acct1.AccountUUID] = append(op.Items[acct1.AccountUUID], varItem("PATH", "p"))
	op.Items[acct2.AccountUUID] = append(op.Items[acct2.AccountUUID],
		opItem("item-empty", "Empty", onepass.Field{ID: "field-empty", Type: "CONCEALED", Label: "EMPTY"}))
	res, err := resolve(newRC(op, "shell-env"), "sync")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Candidates) != 2 || len(res.Problems) != 2 {
		t.Fatalf("candidates=%v problems=%+v", labels(res.Candidates), res.Problems)
	}
	token1, token2 := res.Candidates[0].Source, res.Candidates[1].Source
	path, empty := res.Problems[0].Source, res.Problems[1].Source

	tests := []struct {
		name      string
		trusted   []bundle.Source
		trustedC  []string
		untrusted []string
		trustedP  []string
		untrustP  []string
		conflicts []string
	}{
		{
			name:      "nothing trusted: nothing is fatal",
			untrusted: []string{"TOKEN@item-token", "TOKEN@item-token2"},
			untrustP:  []string{"PATH", "EMPTY"},
		},
		{
			name:      "one TOKEN trusted: the other is untrusted, not a conflict",
			trusted:   []bundle.Source{token2},
			trustedC:  []string{"TOKEN@item-token2"},
			untrusted: []string{"TOKEN@item-token"},
			untrustP:  []string{"PATH", "EMPTY"},
		},
		{
			name:      "both TOKENs trusted: conflict",
			trusted:   []bundle.Source{token1, token2},
			trustedC:  []string{"TOKEN@item-token", "TOKEN@item-token2"},
			untrustP:  []string{"PATH", "EMPTY"},
			conflicts: []string{"TOKEN"},
		},
		{
			name:      "a trusted source that now fails validation is fatal",
			trusted:   []bundle.Source{token1, empty},
			trustedC:  []string{"TOKEN@item-token"},
			untrusted: []string{"TOKEN@item-token2"},
			trustedP:  []string{"EMPTY"},
			untrustP:  []string{"PATH"},
		},
		{
			name:      "trust under another vault does not match",
			trusted:   []bundle.Source{{AccountUUID: token1.AccountUUID, UserUUID: token1.UserUUID, VaultID: "elsewhere", ItemID: token1.ItemID, FieldID: token1.FieldID, Name: token1.Name}, path},
			untrusted: []string{"TOKEN@item-token", "TOKEN@item-token2"},
			trustedP:  []string{"PATH"},
			untrustP:  []string{"EMPTY"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := res.split(tc.trusted)
			problemNames := func(es []*export.SelectError) []string {
				var out []string
				for _, e := range es {
					out = append(out, e.Source.Name)
				}
				return out
			}
			var conflicts []string
			for _, c := range p.Conflicts {
				conflicts = append(conflicts, c.Name)
			}
			for what, pair := range map[string][2][]string{
				"trusted":            {labels(p.Trusted), tc.trustedC},
				"untrusted":          {labels(p.Untrusted), tc.untrusted},
				"trusted problems":   {problemNames(p.TrustedProblems), tc.trustedP},
				"untrusted problems": {problemNames(p.UntrustedProblems), tc.untrustP},
				"conflicts":          {conflicts, tc.conflicts},
			} {
				if !slices.Equal(pair[0], pair[1]) {
					t.Errorf("%s = %v, want %v", what, pair[0], pair[1])
				}
			}
			if want := len(tc.trustedP)+len(tc.conflicts) > 0; p.Fatal() != want {
				t.Errorf("Fatal() = %v, want %v", p.Fatal(), want)
			}
		})
	}
}

func TestResolveSelectionProblemsNameTheLabel(t *testing.T) {
	res, err := resolve(newRC(fakeOp(varItem("PATH", "p")), "shell-env"), "sync")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Problems) != 1 || res.Problems[0].Source.Name != "PATH" {
		t.Fatalf("problems = %+v", res.Problems)
	}
	if res.InScopeItems != 1 {
		t.Fatalf("an item that yields only errors is still in scope: %d", res.InScopeItems)
	}
}

func TestResolveCountsTaggedItemsWithNoExportableFields(t *testing.T) {
	plain := opItem("item-plain", "Plain", onepass.Field{ID: "u", Type: "STRING", Label: "username", Value: "bob"})
	res, err := resolve(newRC(fakeOp(plain), "shell-env"), "sync")
	if err != nil {
		t.Fatal(err)
	}
	if res.InScopeItems != 1 || len(res.Candidates) != 0 || len(res.Problems) != 0 {
		t.Fatalf("res = %+v", res)
	}
}

func TestResolveUntaggedFetchIsNotInScope(t *testing.T) {
	// The summary carried the tag; the fetched item does not.
	untagged := opItem("item-u", "U", secret("U", "u"))
	untagged.Tags = nil
	fake := fakeOp(untagged)
	op := &wrapClient{Fake: fake}
	op.listTagged = func(context.Context, onepass.Account, string) ([]onepass.Item, error) {
		s := untagged
		s.Tags = []string{"shell-env"}
		s.Fields = nil
		return []onepass.Item{s}, nil
	}
	res, err := resolve(newRC(op, "shell-env"), "sync")
	if err != nil {
		t.Fatal(err)
	}
	if res.InScopeItems != 0 || len(res.Candidates) != 0 {
		t.Fatalf("res = %+v", res)
	}
}

func TestResolveZeroAccountsIsAuthFailure(t *testing.T) {
	_, err := resolve(newRC(&onepass.Fake{}, "shell-env"), "check")
	var ee *ExitError
	if !errors.As(err, &ee) || ee.Code != ExitOnePassAuth || ee.Err != "onepassword_unauthorized" {
		t.Fatalf("err = %v", err)
	}
}

func TestOpFatal(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		acct       onepass.Account
		wantCode   int
		wantErr    string
		wantDetail string
		wantHint   string
	}{
		{
			name: "auth without account", err: &onepass.AuthError{Detail: "locked"},
			wantCode: 2, wantErr: "onepassword_unauthorized",
			wantDetail: "check aborted: 1Password could not be authorized: locked; keychain cache unchanged; unlock 1Password and rerun",
			wantHint:   "op signin",
		},
		{
			name: "auth with account from call", err: &onepass.AuthError{Detail: "locked"}, acct: acct1,
			wantCode: 2, wantErr: "onepassword_unauthorized",
			wantDetail: "check aborted: account my.1password.com could not be authorized: locked; keychain cache unchanged; unlock 1Password and rerun",
			wantHint:   "op signin --account my.1password.com",
		},
		{
			name: "auth with empty detail", err: &onepass.AuthError{}, acct: acct1,
			wantCode: 2, wantErr: "onepassword_unauthorized",
			wantDetail: "check aborted: account my.1password.com could not be authorized; keychain cache unchanged; unlock 1Password and rerun",
			wantHint:   "op signin --account my.1password.com",
		},
		{
			name: "command error", err: &onepass.CommandError{Args: []string{"item", "get", "x"}, ExitCode: 1, Detail: "no such item"}, acct: acct1,
			wantCode: 1, wantErr: "onepassword_failed",
			wantDetail: "check aborted: account my.1password.com: get item x: op [item get x]: exit 1: no such item; keychain cache unchanged",
			wantHint:   "fix the 1Password error and rerun envsec check",
		},
		{
			name: "timeout is an auth failure", err: &onepass.AuthError{Account: acct1, Detail: "op timed out after 1s; a Touch ID or unlock prompt was probably unanswered", Err: onepass.ErrTimeout}, acct: acct1,
			wantCode: 2, wantErr: "onepassword_unauthorized",
			wantDetail: "check aborted: account my.1password.com could not be authorized: op timed out after 1s; a Touch ID or unlock prompt was probably unanswered; keychain cache unchanged; unlock 1Password and rerun",
			wantHint:   "op signin --account my.1password.com",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var ee *ExitError
			if !errors.As(opFatal("check", tc.err, tc.acct, "get item x"), &ee) {
				t.Fatal("not an ExitError")
			}
			if ee.Code != tc.wantCode || ee.Err != tc.wantErr || ee.Detail != tc.wantDetail || ee.Hint != tc.wantHint {
				t.Fatalf("got %+v", ee)
			}
		})
	}
}
