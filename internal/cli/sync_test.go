package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tammersaleh/envsec/internal/bundle"
	"github.com/tammersaleh/envsec/internal/keychain"
	"github.com/tammersaleh/envsec/internal/onepass"
	"github.com/tammersaleh/envsec/internal/trustpicker"
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

func trailer(n int) string {
	return fmt.Sprintf(`{"_meta":{"has_more":false,"error_count":%d}}`, n) + "\n"
}

// row is a diff or compare row for a var under acct1.
func row(name, status string) string {
	return fmt.Sprintf(`{"var":%q,"account":"my.1password.com","status":%q}`, name, status) + "\n"
}

// provRow is the row that carries the provenance of the source varItem(name)
// yields under acct1.
func provRow(name, status, detail string) string {
	low := strings.ToLower(name)
	return fmt.Sprintf(`{"var":%q,"account":"my.1password.com","vault":"Private","vault_id":"vault","item":"Title %s","item_id":"item-%s","field_id":"field-%s","source_id":%q,"status":%q,"detail":%q}`,
		name, name, low, low, src(name).ID(), status, detail) + "\n"
}

func untrustedRow(name string) string {
	return provRow(name, "untrusted", "source is not trusted")
}

// src2 is a source under acct2.
func src2(itemID, name string) bundle.Source {
	return bundle.Source{AccountUUID: "ACCT2", UserUUID: "USER2", VaultID: "vault", ItemID: itemID, FieldID: "field-" + strings.ToLower(name), Name: name}
}

// picking is an available picker that confirms exactly srcs.
func picking(srcs ...bundle.Source) *trustpicker.Fake {
	f := &trustpicker.Fake{IsAvailable: true, Selection: []string{}}
	for _, s := range srcs {
		f.Selection = append(f.Selection, s.ID())
	}
	return f
}

// trustedIDs returns the stored trusted source ids, sorted as stored.
func trustedIDs(t *testing.T, kc *keychain.Fake) []string {
	t.Helper()
	var ids []string
	for _, s := range decodeFake(t, kc).TrustedSources {
		ids = append(ids, s.Name+"="+s.ID())
	}
	return ids
}

func wantTrusted(t *testing.T, kc *keychain.Fake, srcs ...bundle.Source) {
	t.Helper()
	var want []string
	for _, s := range srcs {
		want = append(want, s.Name+"="+s.ID())
	}
	got := trustedIDs(t, kc)
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("trusted sources = %v, want %v", got, want)
	}
}

func TestSyncFirstRunAddsAll(t *testing.T) {
	kc := &keychain.Fake{}
	picker := picking(src("ZED"), src("ALPHA"))
	r := runSync(t, Deps{Keychain: kc, OnePass: fakeOp(varItem("ZED", "z"), varItem("ALPHA", "a")), Picker: picker})
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
		t.Fatalf("bundle has %d vars or the wrong ones", len(b.Vars))
	}
	wantTrusted(t, kc, src("ALPHA"), src("ZED"))
	if picker.Calls != 1 {
		t.Fatalf("picker calls = %d", picker.Calls)
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
		t.Fatalf("bundle has %d vars", len(b.Vars))
	}
	// The source is gone from 1Password. Its trust is not.
	wantTrusted(t, kc, src("ALPHA"), src("ZED"))
}

// selectionErrorCases are items whose one field fails validation, with the
// error row each yields.
func selectionErrorCases() map[string]struct {
	item onepass.Item
	want string
} {
	cases := map[string]struct {
		item onepass.Item
		want string
	}{
		"denylisted": {varItem("PATH", "x"),
			`{"var":"PATH","account":"my.1password.com","status":"error","detail":"item \"Title PATH\" (item-path): label PATH is denylisted"}`},
		"empty value": {opItem("item-e", "Title E", onepass.Field{ID: "field-e", Type: "CONCEALED", Label: "E"}),
			`{"var":"E","account":"my.1password.com","status":"error","detail":"item \"Title E\" (item-e): E is empty"}`},
		"newline": {varItem("NL", "a\nb"),
			`{"var":"NL","account":"my.1password.com","status":"error","detail":"item \"Title NL\" (item-nl): NL contains control byte 0x0a"}`},
		"carriage return": {varItem("CR", "a\rb"),
			`{"var":"CR","account":"my.1password.com","status":"error","detail":"item \"Title CR\" (item-cr): CR contains control byte 0x0d"}`},
		"tab": {varItem("TAB", "a\tb"),
			`{"var":"TAB","account":"my.1password.com","status":"error","detail":"item \"Title TAB\" (item-tab): TAB contains control byte 0x09"}`},
		"ESC": {varItem("ESC", "a\x1bb"),
			`{"var":"ESC","account":"my.1password.com","status":"error","detail":"item \"Title ESC\" (item-esc): ESC contains control byte 0x1b"}`},
		"DEL": {varItem("DEL", "a\x7fb"),
			`{"var":"DEL","account":"my.1password.com","status":"error","detail":"item \"Title DEL\" (item-del): DEL contains control byte 0x7f"}`},
		"NUL": {varItem("NUL", "a\x00b"),
			`{"var":"NUL","account":"my.1password.com","status":"error","detail":"item \"Title NUL\" (item-nul): NUL contains control byte 0x00"}`},
		"invalid UTF-8": {varItem("BAD_UTF", "a\xffb"),
			`{"var":"BAD_UTF","account":"my.1password.com","status":"error","detail":"item \"Title BAD_UTF\" (item-bad_utf): BAD_UTF is not valid UTF-8"}`},
		"denylisted BASH_ENV": {varItem("BASH_ENV", "x"),
			`{"var":"BASH_ENV","account":"my.1password.com","status":"error","detail":"item \"Title BASH_ENV\" (item-bash_env): label BASH_ENV is denylisted"}`},
		"denylisted MAILPATH": {varItem("MAILPATH", "x"),
			`{"var":"MAILPATH","account":"my.1password.com","status":"error","detail":"item \"Title MAILPATH\" (item-mailpath): label MAILPATH is denylisted"}`},
		"denylisted PROMPT_EOL_MARK": {varItem("PROMPT_EOL_MARK", "x"),
			`{"var":"PROMPT_EOL_MARK","account":"my.1password.com","status":"error","detail":"item \"Title PROMPT_EOL_MARK\" (item-prompt_eol_mark): label PROMPT_EOL_MARK is denylisted"}`},
		"denylisted GIT_CONFIG_COUNT": {varItem("GIT_CONFIG_COUNT", "1"),
			`{"var":"GIT_CONFIG_COUNT","account":"my.1password.com","status":"error","detail":"item \"Title GIT_CONFIG_COUNT\" (item-git_config_count): label GIT_CONFIG_COUNT is denylisted"}`},
		"denylisted GIT_CONFIG_KEY_0": {varItem("GIT_CONFIG_KEY_0", "x"),
			`{"var":"GIT_CONFIG_KEY_0","account":"my.1password.com","status":"error","detail":"item \"Title GIT_CONFIG_KEY_0\" (item-git_config_key_0): label GIT_CONFIG_KEY_0 is denylisted"}`},
		"denylisted GIT_CONFIG_VALUE_0": {varItem("GIT_CONFIG_VALUE_0", "x"),
			`{"var":"GIT_CONFIG_VALUE_0","account":"my.1password.com","status":"error","detail":"item \"Title GIT_CONFIG_VALUE_0\" (item-git_config_value_0): label GIT_CONFIG_VALUE_0 is denylisted"}`},
		"denylisted GIT_CONFIG_PARAMETERS": {varItem("GIT_CONFIG_PARAMETERS", "x"),
			`{"var":"GIT_CONFIG_PARAMETERS","account":"my.1password.com","status":"error","detail":"item \"Title GIT_CONFIG_PARAMETERS\" (item-git_config_parameters): label GIT_CONFIG_PARAMETERS is denylisted"}`},
	}
	return cases
}

// TestSyncTrustedSourceTurnsInvalidLeavesKeychainUntouched: a validation
// failure on a trusted source aborts with no write.
func TestSyncTrustedSourceTurnsInvalidLeavesKeychainUntouched(t *testing.T) {
	for name, tc := range selectionErrorCases() {
		t.Run(name, func(t *testing.T) {
			f := tc.item.Fields[0]
			bad := bundle.Source{AccountUUID: "ACCT", UserUUID: "USER", VaultID: "vault", ItemID: tc.item.ID, FieldID: f.ID, Name: f.Label}
			kc := fakeTrusting(t, []bundle.Source{bad}, sv("ALPHA", "a"))
			before := string(kc.Value)
			r := runSync(t, Deps{Keychain: kc, OnePass: fakeOp(varItem("ALPHA", "new"), tc.item)})
			want := tc.want + "\n" + trailer(1)
			if r.stdout != want {
				t.Fatalf("stdout = %q\nwant %q", r.stdout, want)
			}
			if r.code != 1 || r.stderr != "" || kc.Writes != 0 || string(kc.Value) != before {
				t.Fatalf("code=%d stderr=%q writes=%d", r.code, r.stderr, kc.Writes)
			}
		})
	}
}

// TestSyncUntrustedInvalidSourceIsErrorRowAndDoesNotBlock: anyone who can
// write a tagged item can plant a denylisted or invalid field. It costs an
// error row and exit 1. The trusted vars are still written.
func TestSyncUntrustedInvalidSourceIsErrorRowAndDoesNotBlock(t *testing.T) {
	for name, tc := range selectionErrorCases() {
		t.Run(name, func(t *testing.T) {
			kc := fakeBundle(t, sv("ALPHA", "old"))
			picker := &trustpicker.Fake{IsAvailable: true}
			r := runSync(t, Deps{Keychain: kc, OnePass: fakeOp(varItem("ALPHA", "new"), tc.item), Picker: picker})
			want := row("ALPHA", "changed") + tc.want + "\n" + trailer(1)
			if r.stdout != want {
				t.Fatalf("stdout = %q\nwant %q", r.stdout, want)
			}
			if r.code != 1 || r.stderr != "" || kc.Writes != 1 || picker.Calls != 0 {
				t.Fatalf("code=%d stderr=%q writes=%d picker calls=%d", r.code, r.stderr, kc.Writes, picker.Calls)
			}
			b := decodeFake(t, kc)
			if len(b.Vars) != 1 || b.Vars[0] != sv("ALPHA", "new") {
				t.Fatalf("bundle has %d vars or ALPHA was not updated", len(b.Vars))
			}
			wantTrusted(t, kc, src("ALPHA"))
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
	kc := fakeTrusting(t, []bundle.Source{src("TOKEN"), src2("item-token2", "TOKEN")})
	r := runSync(t, Deps{Keychain: kc, OnePass: twoAccountOp()})
	want := `{"var":"TOKEN","account":"","status":"conflict","detail":"conflict: TOKEN is defined by item item-token (my.1password.com) and item item-token2 (other.1password.com)"}` + "\n" +
		`{"_meta":{"has_more":false,"error_count":1}}` + "\n"
	if r.stdout != want {
		t.Fatalf("stdout = %q\nwant %q", r.stdout, want)
	}
	if r.code != 1 || kc.Writes != 0 {
		t.Fatalf("code=%d writes=%d", r.code, kc.Writes)
	}
}

func TestSyncSameLabelTwiceInOneItemIsConflict(t *testing.T) {
	first := bundle.Source{AccountUUID: "ACCT", UserUUID: "USER", VaultID: "vault", ItemID: "item-twice", FieldID: "field-token", Name: "TOKEN"}
	second := first
	second.FieldID = "field-token-2"
	kc := fakeTrusting(t, []bundle.Source{first, second})
	twice := opItem("item-twice", "Twice", secret("TOKEN", "one"), onepass.Field{ID: "field-token-2", Type: "CONCEALED", Label: "TOKEN", Value: marker + "-two"})
	r := runSync(t, Deps{Keychain: kc, OnePass: fakeOp(twice)})
	want := `{"var":"TOKEN","account":"","status":"conflict","detail":"conflict: TOKEN is defined by item item-twice field field-token (my.1password.com) and item item-twice field field-token-2 (my.1password.com)"}` + "\n" +
		`{"_meta":{"has_more":false,"error_count":1}}` + "\n"
	if r.stdout != want {
		t.Fatalf("stdout = %q\nwant %q", r.stdout, want)
	}
	if r.code != 1 || kc.Writes != 0 {
		t.Fatalf("code=%d writes=%d", r.code, kc.Writes)
	}
}

// TestSyncNullOrMissingFieldsOnFetchedItemAbortsWithoutWrite drives the real
// onepass client with a scripted runner. The old bundle holds vars from items
// A and B; item A's fetch comes back with the right id and tag but no fields
// array. Treating that as "no fields" would silently drop A's var, so it must
// be a failure with no write.
func TestSyncNullOrMissingFieldsOnFetchedItemAbortsWithoutWrite(t *testing.T) {
	for name, getA := range map[string]string{
		"fields null":    `{"id":"item-alpha","title":"Title ALPHA","tags":["shell-env"],"fields":null}`,
		"fields missing": `{"id":"item-alpha","title":"Title ALPHA","tags":["shell-env"]}`,
	} {
		t.Run(name, func(t *testing.T) {
			kc := fakeBundle(t, sv("ALPHA", "a"), sv("BETA", "b"))
			mustJSON := func(v any) []byte {
				b, err := json.Marshal(v)
				if err != nil {
					t.Fatal(err)
				}
				return b
			}
			accounts := mustJSON([]onepass.Account{acct1})
			list := mustJSON([]onepass.Item{
				{ID: "item-alpha", Title: "Title ALPHA", Tags: []string{"shell-env"}},
				{ID: "item-beta", Title: "Title BETA", Tags: []string{"shell-env"}},
			})
			getB := mustJSON(varItem("BETA", "b"))
			runner := func(_ context.Context, _ string, args ...string) ([]byte, []byte, int, error) {
				switch {
				case args[0] == "account":
					return accounts, nil, 0, nil
				case args[0] == "item" && args[1] == "list":
					return list, nil, 0, nil
				case args[0] == "item" && args[1] == "get" && args[2] == "item-alpha":
					return []byte(getA), nil, 0, nil
				case args[0] == "item" && args[1] == "get" && args[2] == "item-beta":
					return getB, nil, 0, nil
				}
				t.Fatalf("unexpected op args %q", args)
				return nil, nil, 1, nil
			}
			op := onepass.New(onepass.Options{Runner: runner})
			r := runSync(t, Deps{Keychain: kc, OnePass: op})
			if r.code != 1 || r.stdout != "" || kc.Writes != 0 {
				t.Fatalf("code=%d writes=%d stdout=%q stderr=%q", r.code, kc.Writes, r.stdout, r.stderr)
			}
			for _, s := range []string{`"error":"onepassword_failed"`, "get item item-alpha", "fields", "keychain cache unchanged"} {
				if !strings.Contains(r.stderr, s) {
					t.Errorf("stderr %q lacks %q", r.stderr, s)
				}
			}
		})
	}
}

func TestSyncAuthErrorFromAccounts(t *testing.T) {
	kc := fakeBundle(t, sv("ALPHA", "a"))
	op := &onepass.Fake{Errs: onepass.FakeErrs{Accounts: &onepass.AuthError{Detail: "not signed in"}}}
	r := runSync(t, Deps{Keychain: kc, OnePass: op})
	want := `{"error":"onepassword_unauthorized","detail":"sync aborted: 1Password could not be authorized: not signed in; keychain cache unchanged; unlock 1Password and rerun","hint":"op signin"}` + "\n"
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
	want := `{"error":"onepassword_unauthorized","detail":"sync aborted: account other.1password.com could not be authorized: Touch ID dismissed; keychain cache unchanged; unlock 1Password and rerun","hint":"op signin --account other.1password.com"}` + "\n"
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
	want := `{"error":"account_missing","detail":"account ACCT user USER (my.1password.com) is in the keychain bundle but not in op account list","hint":"envsec sync --forget-account ACCT"}` + "\n"
	if r.code != 1 || r.stdout != "" || r.stderr != want || kc.Writes != 0 {
		t.Fatalf("code=%d writes=%d stdout=%q stderr=%q", r.code, kc.Writes, r.stdout, r.stderr)
	}

	// Forgetting the account drops its trust too. Nothing is trusted then,
	// so the picker opens for what the remaining account offers.
	picker := picking(src2("item-other", "OTHER"))
	r = runSync(t, Deps{Keychain: kc, OnePass: op, Picker: picker}, "--forget-account", "ACCT")
	wantOut := `{"var":"ALPHA","account":"my.1password.com","status":"removed"}` + "\n" +
		`{"var":"OTHER","account":"other.1password.com","status":"added"}` + "\n" + trailerOK
	if r.code != 0 || r.stdout != wantOut || r.stderr != "" || kc.Writes != 1 {
		t.Fatalf("code=%d writes=%d stdout=%q stderr=%q", r.code, kc.Writes, r.stdout, r.stderr)
	}
	if b := decodeFake(t, kc); len(b.Vars) != 1 || b.Vars[0].Name != "OTHER" || b.Vars[0].AccountUUID != "ACCT2" {
		t.Fatalf("bundle has %d vars", len(b.Vars))
	}
	wantTrusted(t, kc, src2("item-other", "OTHER"))
}

// TestSyncForgetAccountKeepsOtherTrust: --forget-account drops the trusted
// sources of that account only.
func TestSyncForgetAccountKeepsOtherTrust(t *testing.T) {
	other := bundle.Var{Name: "OTHER", Value: marker + "-o", AccountUUID: "ACCT2", UserUUID: "USER2", AccountURL: "other.1password.com", VaultID: "vault", ItemID: "item-other", FieldID: "field-other"}
	kc := fakeTrusting(t, []bundle.Source{src("GONE")}, sv("ALPHA", "a"), other)
	op := &onepass.Fake{AccountList: []onepass.Account{acct2}, Items: map[string][]onepass.Item{
		acct2.AccountUUID: {opItem("item-other", "Other", secret("OTHER", "o"))},
	}}
	picker := &trustpicker.Fake{IsAvailable: true}
	r := runSync(t, Deps{Keychain: kc, OnePass: op, Picker: picker}, "--forget-account", "ACCT")
	wantOut := row("ALPHA", "removed") + `{"var":"OTHER","account":"other.1password.com","status":"unchanged"}` + "\n" + trailerOK
	if r.code != 0 || r.stdout != wantOut || r.stderr != "" || kc.Writes != 1 || picker.Calls != 0 {
		t.Fatalf("code=%d writes=%d picker=%d stdout=%q stderr=%q", r.code, kc.Writes, picker.Calls, r.stdout, r.stderr)
	}
	wantTrusted(t, kc, src2("item-other", "OTHER"))
}

// TestSyncAccountKnownOnlyFromTrustedSourcesIsGuarded: a trusted source with
// no var still names its account, so that account cannot vanish silently.
func TestSyncAccountKnownOnlyFromTrustedSourcesIsGuarded(t *testing.T) {
	gone := bundle.Source{AccountUUID: "ACCT9", UserUUID: "USER9", VaultID: "vault", ItemID: "item-gone", FieldID: "field-gone", Name: "GONE"}
	kc := fakeTrusting(t, []bundle.Source{gone}, sv("ALPHA", "a"))
	r := runSync(t, Deps{Keychain: kc, OnePass: fakeOp(varItem("ALPHA", "a"))})
	want := `{"error":"account_missing","detail":"account ACCT9 user USER9 is in the keychain bundle but not in op account list","hint":"envsec sync --forget-account ACCT9"}` + "\n"
	if r.code != 1 || r.stdout != "" || r.stderr != want || kc.Writes != 0 {
		t.Fatalf("code=%d writes=%d stdout=%q stderr=%q", r.code, kc.Writes, r.stdout, r.stderr)
	}
	r = runSync(t, Deps{Keychain: kc, OnePass: fakeOp(varItem("ALPHA", "a"))}, "--forget-account", "ACCT9")
	if r.code != 0 || r.stdout != row("ALPHA", "unchanged")+trailerOK || kc.Writes != 1 {
		t.Fatalf("code=%d writes=%d stdout=%q stderr=%q", r.code, kc.Writes, r.stdout, r.stderr)
	}
	wantTrusted(t, kc, src("ALPHA"))
}

// TestSyncGuardsRunBeforeThePicker: a guard failure must not come after the
// user already picked.
func TestSyncGuardsRunBeforeThePicker(t *testing.T) {
	t.Run("vanished account", func(t *testing.T) {
		kc := legacyBundle(t, sv("ALPHA", "a"))
		op := &onepass.Fake{AccountList: []onepass.Account{acct2}, Items: map[string][]onepass.Item{
			acct2.AccountUUID: {opItem("item-other", "Other", secret("OTHER", "o"))},
		}}
		picker := &trustpicker.Fake{IsAvailable: true}
		r := runSync(t, Deps{Keychain: kc, OnePass: op, Picker: picker})
		if r.code != 1 || r.stdout != "" || !strings.Contains(r.stderr, `"error":"account_missing"`) || kc.Writes != 0 || picker.Calls != 0 {
			t.Fatalf("code=%d writes=%d picker=%d stdout=%q stderr=%q", r.code, kc.Writes, picker.Calls, r.stdout, r.stderr)
		}
	})
	t.Run("zero items", func(t *testing.T) {
		kc := legacyBundle(t, sv("ALPHA", "a"))
		picker := &trustpicker.Fake{IsAvailable: true}
		r := runSync(t, Deps{Keychain: kc, OnePass: fakeOp(), Picker: picker})
		if r.code != 1 || r.stdout != "" || !strings.Contains(r.stderr, `"error":"prune_refused"`) || kc.Writes != 0 || picker.Calls != 0 {
			t.Fatalf("code=%d writes=%d picker=%d stdout=%q stderr=%q", r.code, kc.Writes, picker.Calls, r.stdout, r.stderr)
		}
	})
}

func TestSyncSameAccountDifferentUserIsMissing(t *testing.T) {
	// Same account UUID, new user UUID: a different identity. Not dropped
	// silently; --forget-account on the account UUID forgets every old
	// identity under it.
	kc := fakeBundle(t, sv("ALPHA", "a"))
	sameAcctNewUser := acct1
	sameAcctNewUser.UserUUID = "USER-NEW"
	op := &onepass.Fake{AccountList: []onepass.Account{sameAcctNewUser}, Items: map[string][]onepass.Item{
		acct1.AccountUUID: {varItem("ALPHA", "a")},
	}}
	r := runSync(t, Deps{Keychain: kc, OnePass: op})
	want := `{"error":"account_missing","detail":"account ACCT user USER (my.1password.com) is in the keychain bundle but not in op account list","hint":"envsec sync --forget-account ACCT"}` + "\n"
	if r.code != 1 || r.stdout != "" || r.stderr != want || kc.Writes != 0 {
		t.Fatalf("code=%d writes=%d stdout=%q stderr=%q", r.code, kc.Writes, r.stdout, r.stderr)
	}

	newUser := src("ALPHA")
	newUser.UserUUID = "USER-NEW"
	r = runSync(t, Deps{Keychain: kc, OnePass: op, Picker: picking(newUser)}, "--forget-account", "ACCT")
	wantOut := `{"var":"ALPHA","account":"my.1password.com","status":"changed"}` + "\n" + trailerOK
	if r.code != 0 || r.stdout != wantOut || kc.Writes != 1 {
		t.Fatalf("code=%d writes=%d stdout=%q stderr=%q", r.code, kc.Writes, r.stdout, r.stderr)
	}
	if b := decodeFake(t, kc); len(b.Vars) != 1 || b.Vars[0].UserUUID != "USER-NEW" {
		t.Fatalf("bundle has %d vars", len(b.Vars))
	}
	wantTrusted(t, kc, newUser)
}

func TestSyncPruneRefusedWithoutFlag(t *testing.T) {
	kc := fakeBundle(t, sv("ALPHA", "a"), sv("ZED", "z"))
	r := runSync(t, Deps{Keychain: kc, OnePass: fakeOp()})
	want := `{"error":"prune_refused","detail":"no items tagged \"shell-env\" in any account; the keychain bundle holds 2 var(s); refusing to write an empty bundle","hint":"envsec sync --prune-all"}` + "\n"
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
		t.Fatalf("bundle has %d vars", len(b.Vars))
	}
	// --prune-all empties vars and keeps every trust decision.
	wantTrusted(t, kc, src("ALPHA"), src("ZED"))
}

func TestSyncZeroItemsFirstRunRefusedWithoutPruneAll(t *testing.T) {
	// No in-scope items anywhere usually means the wrong tag or the wrong
	// account, so an empty bundle needs --prune-all even on a first run.
	for name, kc := range map[string]*keychain.Fake{
		"no bundle":    {},
		"empty bundle": fakeBundle(t),
	} {
		t.Run(name, func(t *testing.T) {
			r := runSync(t, Deps{Keychain: kc, OnePass: fakeOp()}, "--tag", "nope")
			want := `{"error":"prune_refused","detail":"no items tagged \"nope\" in any account; the keychain bundle holds 0 var(s); refusing to write an empty bundle","hint":"envsec sync --prune-all"}` + "\n"
			if r.code != 1 || r.stdout != "" || r.stderr != want || kc.Writes != 0 {
				t.Fatalf("code=%d writes=%d stdout=%q stderr=%q", r.code, kc.Writes, r.stdout, r.stderr)
			}

			r = runSync(t, Deps{Keychain: kc, OnePass: fakeOp()}, "--tag", "nope", "--prune-all")
			if r.code != 0 || r.stdout != trailerOK || r.stderr != "" || kc.Writes != 1 {
				t.Fatalf("with --prune-all: code=%d writes=%d stdout=%q stderr=%q", r.code, kc.Writes, r.stdout, r.stderr)
			}
			if b := decodeFake(t, kc); len(b.Vars) != 0 || len(b.TrustedSources) != 0 {
				t.Fatalf("bundle has %d vars and %d trusted sources", len(b.Vars), len(b.TrustedSources))
			}
		})
	}
}

func TestSyncTaggedItemWithNoExportableFieldsIsInScope(t *testing.T) {
	// The tag search found something, so the guard is satisfied even though
	// it yields no vars; the old var is removed.
	kc := fakeBundle(t, sv("ALPHA", "a"))
	plain := opItem("item-plain", "Plain", onepass.Field{ID: "u", Type: "STRING", Label: "username", Value: "bob"})
	r := runSync(t, Deps{Keychain: kc, OnePass: fakeOp(plain)})
	want := `{"var":"ALPHA","account":"my.1password.com","status":"removed"}` + "\n" + trailerOK
	if r.code != 0 || r.stdout != want || kc.Writes != 1 {
		t.Fatalf("code=%d writes=%d stdout=%q stderr=%q", r.code, kc.Writes, r.stdout, r.stderr)
	}
}

func TestSyncZeroAccountsIsExit2(t *testing.T) {
	kc := fakeBundle(t, sv("ALPHA", "a"))
	r := runSync(t, Deps{Keychain: kc, OnePass: &onepass.Fake{}})
	want := `{"error":"onepassword_unauthorized","detail":"sync aborted: 1Password could not be authorized: no 1Password accounts are signed in; keychain cache unchanged; unlock 1Password and rerun","hint":"op signin"}` + "\n"
	if r.code != 2 || r.stdout != "" || r.stderr != want || kc.Writes != 0 {
		t.Fatalf("code=%d writes=%d stdout=%q stderr=%q", r.code, kc.Writes, r.stdout, r.stderr)
	}
}

func TestSyncOpTimeoutIsExit2(t *testing.T) {
	kc := fakeBundle(t, sv("ALPHA", "a"))
	op := fakeOp(varItem("ALPHA", "a"))
	op.Errs.ListTagged = &onepass.AuthError{Account: acct1, Detail: "op timed out after 60s; a Touch ID or unlock prompt was probably unanswered", Err: onepass.ErrTimeout}
	r := runSync(t, Deps{Keychain: kc, OnePass: op})
	want := `{"error":"onepassword_unauthorized","detail":"sync aborted: account my.1password.com could not be authorized: op timed out after 60s; a Touch ID or unlock prompt was probably unanswered; keychain cache unchanged; unlock 1Password and rerun","hint":"op signin --account my.1password.com"}` + "\n"
	if r.code != 2 || r.stdout != "" || r.stderr != want || kc.Writes != 0 {
		t.Fatalf("code=%d writes=%d stdout=%q stderr=%q", r.code, kc.Writes, r.stdout, r.stderr)
	}
}

// TestSyncBlankListOutputOnSecondAccountAbortsWithoutWrite drives the real
// onepass client with a scripted runner: account A lists and fetches fine,
// account B's `op item list` prints nothing. That must be a failure, not an
// empty account, or sync would silently drop B's vars from the bundle.
func TestSyncBlankListOutputOnSecondAccountAbortsWithoutWrite(t *testing.T) {
	kc := fakeBundle(t, sv("ALPHA", "a"), bundle.Var{
		Name: "BETA", Value: marker + "-b", AccountUUID: "ACCT2", UserUUID: "USER2", AccountURL: "other.1password.com", VaultID: "vault", ItemID: "item-beta", FieldID: "field-beta",
	})
	mustJSON := func(v any) []byte {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	accounts := mustJSON([]onepass.Account{acct1, acct2})
	listA := mustJSON([]onepass.Item{{ID: "item-alpha", Title: "Title ALPHA", Tags: []string{"shell-env"}}})
	getA := mustJSON(varItem("ALPHA", "a"))
	runner := func(_ context.Context, _ string, args ...string) ([]byte, []byte, int, error) {
		switch {
		case args[0] == "account":
			return accounts, nil, 0, nil
		case args[0] == "item" && args[1] == "list" && args[len(args)-1] == acct1.AccountUUID:
			return listA, nil, 0, nil
		case args[0] == "item" && args[1] == "list":
			return []byte("\n"), nil, 0, nil
		case args[0] == "item" && args[1] == "get":
			return getA, nil, 0, nil
		}
		t.Fatalf("unexpected op args %q", args)
		return nil, nil, 1, nil
	}
	op := onepass.New(onepass.Options{Runner: runner})
	r := runSync(t, Deps{Keychain: kc, OnePass: op})
	if r.code != 1 || r.stdout != "" || kc.Writes != 0 {
		t.Fatalf("code=%d writes=%d stdout=%q stderr=%q", r.code, kc.Writes, r.stdout, r.stderr)
	}
	for _, s := range []string{`"error":"onepassword_failed"`, "account other.1password.com", "malformed output", "keychain cache unchanged"} {
		if !strings.Contains(r.stderr, s) {
			t.Errorf("stderr %q lacks %q", r.stderr, s)
		}
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
	r := runSync(t, Deps{Keychain: kc, OnePass: op, Picker: picking(src("ALPHA"))})
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
	r = runCLI(t, Deps{Keychain: kc, OnePass: op, Picker: picking(src("ALPHA")), Now: func() time.Time { return fixedTime }}, "sync")
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
	r := runSync(t, Deps{Keychain: kc, OnePass: fakeOp(varItem("ALPHA", "a")), Picker: picking(src("ALPHA"))})
	want := `{"error":"keychain_unavailable","detail":"keychain unavailable: locked","hint":"unlock the login keychain and rerun envsec sync"}` + "\n"
	if r.code != 4 || r.stdout != "" || r.stderr != want {
		t.Fatalf("code=%d stdout=%q stderr=%q", r.code, r.stdout, r.stderr)
	}
}

func TestSyncKeychainWriteLocked(t *testing.T) {
	kc := &keychain.Fake{WriteErr: &keychain.LockedError{KeychainPath: "/k/login.keychain-db"}}
	r := runSync(t, Deps{Keychain: kc, OnePass: fakeOp(varItem("ALPHA", "a")), Picker: picking(src("ALPHA"))})
	want := `{"error":"keychain_locked","detail":"keychain locked: /k/login.keychain-db (no UI session; typical over ssh)","hint":"security unlock-keychain /k/login.keychain-db"}` + "\n"
	if r.code != 4 || r.stdout != "" || r.stderr != want {
		t.Fatalf("code=%d stdout=%q stderr=%q", r.code, r.stdout, r.stderr)
	}
}

func TestSyncKeychainReadLocked(t *testing.T) {
	kc := &keychain.Fake{ReadErr: &keychain.LockedError{KeychainPath: "/k/login.keychain-db"}}
	r := runSync(t, Deps{Keychain: kc, OnePass: fakeOp(varItem("ALPHA", "a"))})
	if r.code != 4 || r.stdout != "" || !strings.Contains(r.stderr, `"error":"keychain_locked"`) || kc.Writes != 0 {
		t.Fatalf("code=%d writes=%d stdout=%q stderr=%q", r.code, kc.Writes, r.stdout, r.stderr)
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
	other := varItem("BETA", "b")
	other.Tags = []string{"other"}
	op := fakeOp(varItem("ALPHA", "a"), other)
	r := runSync(t, Deps{Keychain: kc, OnePass: op, Picker: picking(src("BETA"))}, "--tag", "other")
	want := `{"var":"BETA","account":"my.1password.com","status":"added"}` + "\n" + trailerOK
	if r.code != 0 || r.stdout != want {
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
