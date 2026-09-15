package cli

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tammersaleh/envsec/internal/bundle"
	"github.com/tammersaleh/envsec/internal/keychain"
	"github.com/tammersaleh/envsec/internal/onepass"
)

// Every fake secret carries this marker so tests can assert that no output
// stream ever contains a value.
const marker = "sekrit"

var (
	acct1 = onepass.Account{URL: "my.1password.com", Email: "me@example.com", UserUUID: "USER", AccountUUID: "ACCT"}
	acct2 = onepass.Account{URL: "other.1password.com", Email: "me@example.com", UserUUID: "USER2", AccountUUID: "ACCT2"}
)

// secret builds a CONCEALED field. The value is prefixed with marker.
func secret(label, value string) onepass.Field {
	return onepass.Field{ID: "field-" + strings.ToLower(label), Type: "CONCEALED", Label: label, Value: marker + "-" + value}
}

// opItem builds a tagged item.
func opItem(id, title string, fields ...onepass.Field) onepass.Item {
	return onepass.Item{ID: id, Title: title, Vault: onepass.Vault{ID: "vault", Name: "Private"}, Tags: []string{"shell-env"}, Fields: fields}
}

// varItem builds the one-var item whose provenance matches v(name, ...) from
// root_test.go for account acct1.
func varItem(name, value string) onepass.Item {
	return opItem("item-"+strings.ToLower(name), "Title "+name, secret(name, value))
}

// sv is v() with the marker prefix secret() adds, so bundles built for the
// keychain fake compare equal to what resolve produces.
func sv(name, value string) bundle.Var {
	return v(name, marker+"-"+value)
}

func fakeOp(items ...onepass.Item) *onepass.Fake {
	return &onepass.Fake{AccountList: []onepass.Account{acct1}, Items: map[string][]onepass.Item{acct1.AccountUUID: items}}
}

// useTempLock points the sync lock at a per-test directory.
func useTempLock(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sync.lock")
	orig := lockPath
	lockPath = func() (string, error) { return path, nil }
	t.Cleanup(func() { lockPath = orig })
	return path
}

// runSync runs `envsec sync args...` with a fixed clock and a temp lock, and
// fails the test if any output stream leaks a value.
func runSync(t *testing.T, deps Deps, args ...string) result {
	t.Helper()
	useTempLock(t)
	if deps.Now == nil {
		deps.Now = func() time.Time { return fixedTime }
	}
	r := runCLI(t, deps, append([]string{"sync"}, args...)...)
	noValues(t, r)
	return r
}

func noValues(t *testing.T, r result) {
	t.Helper()
	if strings.Contains(r.stdout, marker) || strings.Contains(r.stderr, marker) {
		t.Fatalf("output leaked a value\nstdout=%q\nstderr=%q", r.stdout, r.stderr)
	}
}

func decodeFake(t *testing.T, kc *keychain.Fake) bundle.Bundle {
	t.Helper()
	b, err := bundle.Decode(kc.Value)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

const trailerOK = `{"_meta":{"has_more":false,"error_count":0}}` + "\n"

func TestSyncFirstRunAddsAll(t *testing.T) {
	kc := &keychain.Fake{}
	r := runSync(t, Deps{Keychain: kc, OnePass: fakeOp(varItem("ZED", "z"), varItem("ALPHA", "a"))})
	want := `{"var":"ALPHA","account":"my.1password.com","status":"added"}` + "\n" +
		`{"var":"ZED","account":"my.1password.com","status":"added"}` + "\n" + trailerOK
	if r.stdout != want || r.code != 0 || r.stderr != "" {
		t.Fatalf("code=%d stderr=%q stdout=%q\nwant %q", r.code, r.stderr, r.stdout, want)
	}
	if kc.Writes != 1 {
		t.Fatalf("writes=%d", kc.Writes)
	}
	b := decodeFake(t, kc)
	if !b.GeneratedAt.Equal(fixedTime) || len(b.Vars) != 2 || b.Vars[0] != sv("ALPHA", "a") || b.Vars[1] != sv("ZED", "z") {
		t.Fatalf("bundle = %+v", b)
	}
}

func TestSyncSecondRunUnchanged(t *testing.T) {
	kc := fakeBundle(t, sv("ALPHA", "a"))
	r := runSync(t, Deps{Keychain: kc, OnePass: fakeOp(varItem("ALPHA", "a"))})
	want := `{"var":"ALPHA","account":"my.1password.com","status":"unchanged"}` + "\n" + trailerOK
	if r.stdout != want || r.code != 0 || kc.Writes != 1 {
		t.Fatalf("code=%d writes=%d stdout=%q", r.code, kc.Writes, r.stdout)
	}
}

func TestSyncChangedValue(t *testing.T) {
	kc := fakeBundle(t, sv("ALPHA", "old"))
	r := runSync(t, Deps{Keychain: kc, OnePass: fakeOp(varItem("ALPHA", "new"))})
	want := `{"var":"ALPHA","account":"my.1password.com","status":"changed"}` + "\n" + trailerOK
	if r.stdout != want || r.code != 0 || kc.Writes != 1 {
		t.Fatalf("code=%d writes=%d stdout=%q", r.code, kc.Writes, r.stdout)
	}
	if got := decodeFake(t, kc).Vars[0].Value; got != marker+"-new" {
		t.Fatalf("stored value = %q", got)
	}
}

func TestSyncRemovedVar(t *testing.T) {
	kc := fakeBundle(t, sv("ALPHA", "a"), sv("ZED", "z"))
	r := runSync(t, Deps{Keychain: kc, OnePass: fakeOp(varItem("ALPHA", "a"))})
	want := `{"var":"ALPHA","account":"my.1password.com","status":"unchanged"}` + "\n" +
		`{"var":"ZED","account":"my.1password.com","status":"removed"}` + "\n" + trailerOK
	if r.stdout != want || r.code != 0 || kc.Writes != 1 {
		t.Fatalf("code=%d writes=%d stdout=%q", r.code, kc.Writes, r.stdout)
	}
	if b := decodeFake(t, kc); len(b.Vars) != 1 || b.Vars[0].Name != "ALPHA" {
		t.Fatalf("bundle = %+v", b)
	}
}

func TestSyncSelectionErrorsLeaveKeychainUntouched(t *testing.T) {
	cases := map[string]struct {
		item onepass.Item
		want string
	}{
		"denylisted": {varItem("PATH", "x"),
			`{"var":"","status":"error","detail":"item \"Title PATH\" (item-path): label PATH is denylisted"}`},
		"empty value": {opItem("item-e", "Title E", onepass.Field{ID: "field-e", Type: "CONCEALED", Label: "E"}),
			`{"var":"","status":"error","detail":"item \"Title E\" (item-e): E is empty"}`},
		"newline": {varItem("NL", "a\nb"),
			`{"var":"","status":"error","detail":"item \"Title NL\" (item-nl): NL contains a newline"}`},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			kc := fakeBundle(t, sv("ALPHA", "a"))
			r := runSync(t, Deps{Keychain: kc, OnePass: fakeOp(varItem("ALPHA", "a"), tc.item)})
			want := tc.want + "\n" + `{"_meta":{"has_more":false,"error_count":1}}` + "\n"
			if r.stdout != want {
				t.Fatalf("stdout = %q\nwant %q", r.stdout, want)
			}
			if r.code != 1 || r.stderr != "" || kc.Writes != 0 {
				t.Fatalf("code=%d stderr=%q writes=%d", r.code, r.stderr, kc.Writes)
			}
		})
	}
}

func twoAccountOp() *onepass.Fake {
	return &onepass.Fake{
		AccountList: []onepass.Account{acct1, acct2},
		Items: map[string][]onepass.Item{
			acct1.AccountUUID: {varItem("TOKEN", "one")},
			acct2.AccountUUID: {opItem("item-token2", "Other token", secret("TOKEN", "two"))},
		},
	}
}

func TestSyncConflictAcrossAccounts(t *testing.T) {
	kc := &keychain.Fake{}
	r := runSync(t, Deps{Keychain: kc, OnePass: twoAccountOp()})
	want := `{"var":"TOKEN","status":"error","detail":"conflict: TOKEN is defined by item item-token (my.1password.com) and item item-token2 (other.1password.com)"}` + "\n" +
		`{"_meta":{"has_more":false,"error_count":1}}` + "\n"
	if r.stdout != want {
		t.Fatalf("stdout = %q\nwant %q", r.stdout, want)
	}
	if r.code != 1 || kc.Writes != 0 {
		t.Fatalf("code=%d writes=%d", r.code, kc.Writes)
	}
}

func TestSyncAuthErrorFromAccounts(t *testing.T) {
	kc := fakeBundle(t, sv("ALPHA", "a"))
	op := &onepass.Fake{Errs: onepass.FakeErrs{Accounts: &onepass.AuthError{Detail: "not signed in"}}}
	r := runSync(t, Deps{Keychain: kc, OnePass: op})
	want := `{"error":"onepassword_unauthorized","detail":"sync aborted: 1Password could not be authorized; keychain cache unchanged; unlock 1Password and rerun","hint":"op signin"}` + "\n"
	if r.code != 2 || r.stdout != "" || r.stderr != want || kc.Writes != 0 {
		t.Fatalf("code=%d writes=%d stdout=%q stderr=%q", r.code, kc.Writes, r.stdout, r.stderr)
	}
}

// wrapClient overrides selected methods of an onepass.Fake.
type wrapClient struct {
	*onepass.Fake
	listTagged func(ctx context.Context, account onepass.Account, tag string) ([]onepass.Item, error)
	getItem    func(ctx context.Context, account onepass.Account, id string) (onepass.Item, error)
}

func (w *wrapClient) ListTagged(ctx context.Context, account onepass.Account, tag string) ([]onepass.Item, error) {
	if w.listTagged != nil {
		return w.listTagged(ctx, account, tag)
	}
	return w.Fake.ListTagged(ctx, account, tag)
}

func (w *wrapClient) GetItem(ctx context.Context, account onepass.Account, id string) (onepass.Item, error) {
	if w.getItem != nil {
		return w.getItem(ctx, account, id)
	}
	return w.Fake.GetItem(ctx, account, id)
}

func TestSyncAuthErrorOnSecondAccountGetItem(t *testing.T) {
	kc := &keychain.Fake{}
	fake := twoAccountOp()
	fake.Items[acct2.AccountUUID] = []onepass.Item{opItem("item-other", "Other", secret("OTHER", "o"))}
	op := &wrapClient{Fake: fake}
	op.getItem = func(ctx context.Context, account onepass.Account, id string) (onepass.Item, error) {
		if account.AccountUUID == acct2.AccountUUID {
			return onepass.Item{}, &onepass.AuthError{Account: account, Detail: "Touch ID dismissed"}
		}
		return fake.GetItem(ctx, account, id)
	}
	r := runSync(t, Deps{Keychain: kc, OnePass: op})
	want := `{"error":"onepassword_unauthorized","detail":"sync aborted: account other.1password.com could not be authorized; keychain cache unchanged; unlock 1Password and rerun","hint":"op signin --account other.1password.com"}` + "\n"
	if r.code != 2 || r.stdout != "" || r.stderr != want || kc.Writes != 0 {
		t.Fatalf("code=%d writes=%d stdout=%q stderr=%q", r.code, kc.Writes, r.stdout, r.stderr)
	}
}

func TestSyncOtherOpErrorIsExit1(t *testing.T) {
	kc := fakeBundle(t, sv("ALPHA", "a"))
	op := fakeOp(varItem("ALPHA", "a"))
	op.Errs.ListTagged = &onepass.CommandError{Args: []string{"item", "list"}, ExitCode: 1, Detail: "boom"}
	r := runSync(t, Deps{Keychain: kc, OnePass: op})
	if r.code != 1 || r.stdout != "" || kc.Writes != 0 {
		t.Fatalf("code=%d writes=%d stdout=%q", r.code, kc.Writes, r.stdout)
	}
	for _, s := range []string{`"error":"onepassword_failed"`, "account my.1password.com", `list items tagged \"shell-env\"`, "boom", "keychain cache unchanged"} {
		if !strings.Contains(r.stderr, s) {
			t.Errorf("stderr %q lacks %q", r.stderr, s)
		}
	}
}

func TestSyncAccountVanished(t *testing.T) {
	kc := fakeBundle(t, sv("ALPHA", "a"))
	op := &onepass.Fake{AccountList: []onepass.Account{acct2}, Items: map[string][]onepass.Item{
		acct2.AccountUUID: {opItem("item-other", "Other", secret("OTHER", "o"))},
	}}
	r := runSync(t, Deps{Keychain: kc, OnePass: op})
	want := `{"error":"account_missing","detail":"account ACCT (my.1password.com) is in the keychain bundle but not in op account list","hint":"envsec sync --forget-account ACCT"}` + "\n"
	if r.code != 1 || r.stdout != "" || r.stderr != want || kc.Writes != 0 {
		t.Fatalf("code=%d writes=%d stdout=%q stderr=%q", r.code, kc.Writes, r.stdout, r.stderr)
	}

	r = runSync(t, Deps{Keychain: kc, OnePass: op}, "--forget-account", "ACCT")
	wantOut := `{"var":"ALPHA","account":"my.1password.com","status":"removed"}` + "\n" +
		`{"var":"OTHER","account":"other.1password.com","status":"added"}` + "\n" + trailerOK
	if r.code != 0 || r.stdout != wantOut || r.stderr != "" || kc.Writes != 1 {
		t.Fatalf("code=%d writes=%d stdout=%q stderr=%q", r.code, kc.Writes, r.stdout, r.stderr)
	}
	if b := decodeFake(t, kc); len(b.Vars) != 1 || b.Vars[0].Name != "OTHER" || b.Vars[0].AccountUUID != "ACCT2" {
		t.Fatalf("bundle = %+v", b)
	}
}

func TestSyncPruneRefusedWithoutFlag(t *testing.T) {
	kc := fakeBundle(t, sv("ALPHA", "a"), sv("ZED", "z"))
	r := runSync(t, Deps{Keychain: kc, OnePass: fakeOp()})
	want := `{"error":"prune_refused","detail":"1Password yielded no vars but the keychain bundle holds 2; refusing to empty it","hint":"envsec sync --prune-all"}` + "\n"
	if r.code != 1 || r.stdout != "" || r.stderr != want || kc.Writes != 0 {
		t.Fatalf("code=%d writes=%d stdout=%q stderr=%q", r.code, kc.Writes, r.stdout, r.stderr)
	}

	r = runSync(t, Deps{Keychain: kc, OnePass: fakeOp()}, "--prune-all")
	wantOut := `{"var":"ALPHA","account":"my.1password.com","status":"removed"}` + "\n" +
		`{"var":"ZED","account":"my.1password.com","status":"removed"}` + "\n" + trailerOK
	if r.code != 0 || r.stdout != wantOut || kc.Writes != 1 {
		t.Fatalf("code=%d writes=%d stdout=%q stderr=%q", r.code, kc.Writes, r.stdout, r.stderr)
	}
	if b := decodeFake(t, kc); len(b.Vars) != 0 {
		t.Fatalf("bundle = %+v", b)
	}
}

func TestSyncZeroVarsFirstRunWritesEmptyBundle(t *testing.T) {
	kc := &keychain.Fake{}
	r := runSync(t, Deps{Keychain: kc, OnePass: fakeOp()})
	if r.code != 0 || r.stdout != trailerOK || kc.Writes != 1 {
		t.Fatalf("code=%d writes=%d stdout=%q stderr=%q", r.code, kc.Writes, r.stdout, r.stderr)
	}
}

func TestSyncDropsItemWhoseFetchedCopyLacksTag(t *testing.T) {
	kc := &keychain.Fake{}
	untagged := opItem("item-untagged", "Untagged", secret("UNTAGGED", "u"))
	untagged.Tags = nil
	fake := fakeOp(varItem("ALPHA", "a"), untagged)
	op := &wrapClient{Fake: fake}
	op.listTagged = func(ctx context.Context, account onepass.Account, tag string) ([]onepass.Item, error) {
		items, err := fake.ListTagged(ctx, account, tag)
		// Summary still carries the tag; the full item no longer does.
		stale := untagged
		stale.Tags = []string{tag}
		stale.Fields = nil
		return append(items, stale), err
	}
	r := runSync(t, Deps{Keychain: kc, OnePass: op})
	want := `{"var":"ALPHA","account":"my.1password.com","status":"added"}` + "\n" + trailerOK
	if r.code != 0 || r.stdout != want || kc.Writes != 1 {
		t.Fatalf("code=%d writes=%d stdout=%q stderr=%q", r.code, kc.Writes, r.stdout, r.stderr)
	}
	fetched := 0
	for _, c := range fake.Calls {
		if c.Method == "GetItem" && c.Arg == "item-untagged" {
			fetched++
		}
	}
	if fetched != 1 {
		t.Fatalf("untagged item fetched %d times, want 1", fetched)
	}
}

func TestSyncLockHeld(t *testing.T) {
	useTempLock(t)
	release, err := acquireLock()
	if err != nil {
		t.Fatal(err)
	}
	kc := &keychain.Fake{}
	op := fakeOp(varItem("ALPHA", "a"))
	// runCLI directly: runSync would swap in a fresh lock path.
	r := runCLI(t, Deps{Keychain: kc, OnePass: op, Now: func() time.Time { return fixedTime }}, "sync")
	if r.code != 1 || r.stdout != "" || !strings.HasPrefix(r.stderr, `{"error":"sync_locked","detail":"another envsec sync holds `) ||
		!strings.HasSuffix(r.stderr, `","hint":"wait for the other envsec sync to finish"}`+"\n") {
		t.Fatalf("code=%d stdout=%q stderr=%q", r.code, r.stdout, r.stderr)
	}
	if kc.Writes != 0 || len(op.Calls) != 0 {
		t.Fatalf("writes=%d op calls=%+v", kc.Writes, op.Calls)
	}

	release()
	r = runCLI(t, Deps{Keychain: kc, OnePass: op, Now: func() time.Time { return fixedTime }}, "sync")
	if r.code != 0 || kc.Writes != 1 {
		t.Fatalf("after release: code=%d writes=%d stderr=%q", r.code, kc.Writes, r.stderr)
	}
}

func TestAcquireLockReleaseAllowsNext(t *testing.T) {
	useTempLock(t)
	release, err := acquireLock()
	if err != nil {
		t.Fatal(err)
	}
	_, err = acquireLock()
	var ee *ExitError
	if !errors.As(err, &ee) || ee.Err != "sync_locked" || ee.Code != 1 {
		t.Fatalf("second acquire: %v", err)
	}
	release()
	release2, err := acquireLock()
	if err != nil {
		t.Fatalf("after release: %v", err)
	}
	release2()
}

func TestSyncKeychainWriteError(t *testing.T) {
	kc := &keychain.Fake{WriteErr: &keychain.UnavailableError{Detail: "locked"}}
	r := runSync(t, Deps{Keychain: kc, OnePass: fakeOp(varItem("ALPHA", "a"))})
	want := `{"error":"keychain_unavailable","detail":"keychain unavailable: locked","hint":"unlock the login keychain and rerun envsec sync"}` + "\n"
	if r.code != 4 || r.stdout != "" || r.stderr != want {
		t.Fatalf("code=%d stdout=%q stderr=%q", r.code, r.stdout, r.stderr)
	}
}

func TestSyncKeychainReadError(t *testing.T) {
	kc := &keychain.Fake{ReadErr: &keychain.UnavailableError{Detail: "locked"}}
	r := runSync(t, Deps{Keychain: kc, OnePass: fakeOp(varItem("ALPHA", "a"))})
	if r.code != 4 || r.stdout != "" || !strings.Contains(r.stderr, `"error":"keychain_unavailable"`) || kc.Writes != 0 {
		t.Fatalf("code=%d writes=%d stdout=%q stderr=%q", r.code, kc.Writes, r.stdout, r.stderr)
	}
}

func TestSyncTagFlagReachesListTagged(t *testing.T) {
	kc := &keychain.Fake{}
	op := fakeOp(varItem("ALPHA", "a"))
	r := runSync(t, Deps{Keychain: kc, OnePass: op}, "--tag", "other")
	if r.code != 0 || r.stdout != trailerOK {
		t.Fatalf("code=%d stdout=%q stderr=%q", r.code, r.stdout, r.stderr)
	}
	found := false
	for _, c := range op.Calls {
		if c.Method == "ListTagged" && c.Arg == "other" && c.AccountUUID == "ACCT" {
			found = true
		}
		if c.Method == "ListTagged" && c.Arg != "other" {
			t.Fatalf("ListTagged called with %q", c.Arg)
		}
	}
	if !found {
		t.Fatalf("calls = %+v", op.Calls)
	}
}
