package cli

import (
	"context"
	"errors"
	"testing"

	"github.com/tammersaleh/envsec/internal/onepass"
)

func newRC(op onepass.Client, tag string) *runContext {
	return &runContext{ctx: context.Background(), globals: Globals{Tag: tag}, deps: Deps{OnePass: op}}
}

func TestResolveWalksEveryAccountBeforeReturning(t *testing.T) {
	op := twoAccountOp()
	op.Items[acct2.AccountUUID] = append(op.Items[acct2.AccountUUID], opItem("item-b", "B", secret("B", "b")))
	res, err := resolve(newRC(op, "shell-env"), "sync")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Accounts) != 2 || len(res.Vars) != 3 {
		t.Fatalf("accounts=%d vars=%d", len(res.Accounts), len(res.Vars))
	}
	if len(res.Problems) != 1 || !res.Problems[0].Conflict || res.Problems[0].Var != "TOKEN" {
		t.Fatalf("problems = %+v", res.Problems)
	}
	// Provenance comes from the account, not the item.
	for _, v := range res.Vars {
		if v.AccountUUID == "" || v.UserUUID == "" || v.AccountURL == "" {
			t.Fatalf("var lacks account provenance: %+v", v)
		}
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

func TestResolveSelectionProblemsHaveNoVar(t *testing.T) {
	res, err := resolve(newRC(fakeOp(varItem("PATH", "p")), "shell-env"), "sync")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Problems) != 1 || res.Problems[0].Var != "" || res.Problems[0].Conflict {
		t.Fatalf("problems = %+v", res.Problems)
	}
}

func TestConflictVar(t *testing.T) {
	if got := conflictVar(errors.New("conflict: TOKEN is defined by item a (x) and item b (y)")); got != "TOKEN" {
		t.Fatalf("got %q", got)
	}
	if got := conflictVar(errors.New("something else")); got != "" {
		t.Fatalf("got %q", got)
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
			wantDetail: "check aborted: 1Password could not be authorized; keychain cache unchanged; unlock 1Password and rerun",
			wantHint:   "op signin",
		},
		{
			name: "auth with account from call", err: &onepass.AuthError{Detail: "locked"}, acct: acct1,
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
			name: "timeout", err: onepass.ErrTimeout, acct: acct1,
			wantCode: 1, wantErr: "onepassword_failed",
			wantDetail: "check aborted: account my.1password.com: get item x: op: command timed out; keychain cache unchanged",
			wantHint:   "fix the 1Password error and rerun envsec check",
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
