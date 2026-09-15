package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tammersaleh/envsec/internal/bundle"
	"github.com/tammersaleh/envsec/internal/keychain"
	"github.com/tammersaleh/envsec/internal/onepass"
)

var fixedTime = time.Date(2026, 9, 14, 17, 2, 11, 0, time.UTC)

func fakeBundle(t *testing.T, vars ...bundle.Var) *keychain.Fake {
	t.Helper()
	raw, err := bundle.Encode(bundle.Bundle{GeneratedAt: fixedTime, Vars: vars})
	if err != nil {
		t.Fatal(err)
	}
	return &keychain.Fake{Value: raw, Exists: true}
}

func v(name, value string) bundle.Var {
	return bundle.Var{
		Name: name, Value: value,
		AccountUUID: "ACCT", UserUUID: "USER", AccountURL: "my.1password.com",
		ItemID: "item-" + strings.ToLower(name), FieldID: "field-" + strings.ToLower(name),
	}
}

type result struct {
	stdout, stderr string
	err            error
	code           int
}

func runCLI(t *testing.T, deps Deps, args ...string) result {
	t.Helper()
	if deps.OnePass == nil {
		deps.OnePass = &onepass.Fake{Errs: onepass.FakeErrs{
			Accounts: errors.New("op must not be called"), ListTagged: errors.New("op must not be called"), GetItem: errors.New("op must not be called"),
		}}
	}
	if deps.Env == nil {
		deps.Env = func(string) string { return "" }
	}
	var out, errb bytes.Buffer
	err := RunWith(args, &out, &errb, deps)
	return result{out.String(), errb.String(), err, ExitCode(err)}
}

func TestVersion(t *testing.T) {
	var out, errb bytes.Buffer
	if err := Run([]string{"version"}, &out, &errb); err != nil {
		t.Fatal(err)
	}
	want := "{\"version\":\"dev\"}\n{\"_meta\":{\"has_more\":false}}\n"
	if out.String() != want {
		t.Fatalf("got %q, want %q", out.String(), want)
	}
	if errb.Len() != 0 {
		t.Fatalf("stderr = %q", errb.String())
	}
}

func TestUnknownCommand(t *testing.T) {
	r := runCLI(t, Deps{}, "bogus")
	if r.code != 1 || r.stdout != "" {
		t.Fatalf("code=%d stdout=%q", r.code, r.stdout)
	}
	want := "{\"error\":\"usage\",\"detail\":\"unexpected argument bogus\",\"hint\":\"envsec --help\"}\n"
	if r.stderr != want {
		t.Fatalf("stderr = %q, want %q", r.stderr, want)
	}
}

func TestHelpExitsZero(t *testing.T) {
	r := runCLI(t, Deps{}, "--help")
	if r.code != 0 || !strings.Contains(r.stderr, "Usage: envsec") || r.stdout != "" {
		t.Fatalf("code=%d stdout=%q stderr=%q", r.code, r.stdout, r.stderr)
	}
}

func TestEnvHappyPath(t *testing.T) {
	r := runCLI(t, Deps{Keychain: fakeBundle(t, v("ZED", "z"), v("ALPHA", "it's $x `y`"))}, "env")
	want := "[[ ${(t)ALPHA} != *readonly* ]] && builtin unset -- ALPHA && builtin export -- ALPHA='it'\\''s $x `y`'\n" +
		"[[ ${(t)ZED} != *readonly* ]] && builtin unset -- ZED && builtin export -- ZED='z'\n" +
		"[[ ${(t)ENVSEC_MANAGED_VARS} != *readonly* ]] && builtin unset -- ENVSEC_MANAGED_VARS && builtin export -- ENVSEC_MANAGED_VARS='ALPHA ZED'\n"
	if r.stdout != want {
		t.Fatalf("stdout = %q\nwant     %q", r.stdout, want)
	}
	if r.code != 0 || r.stderr != "" || r.err != nil {
		t.Fatalf("code=%d err=%v stderr=%q", r.code, r.err, r.stderr)
	}
}

func TestEnvStaleSentinel(t *testing.T) {
	env := func(k string) string {
		if k == managedVar {
			return "STALE ALPHA lower PATH ENVSEC_X bad-name STALE"
		}
		return ""
	}
	r := runCLI(t, Deps{Keychain: fakeBundle(t, v("ALPHA", "a")), Env: env}, "env")
	want := "[[ ${(t)STALE} != *readonly* ]] && builtin unset -- STALE\n" +
		"[[ ${(t)ALPHA} != *readonly* ]] && builtin unset -- ALPHA && builtin export -- ALPHA='a'\n" +
		"[[ ${(t)ENVSEC_MANAGED_VARS} != *readonly* ]] && builtin unset -- ENVSEC_MANAGED_VARS && builtin export -- ENVSEC_MANAGED_VARS='ALPHA'\n"
	if r.stdout != want || r.code != 0 {
		t.Fatalf("code=%d stdout = %q\nwant %q", r.code, r.stdout, want)
	}
}

func TestEnvEmptyBundleClearsSentinel(t *testing.T) {
	env := func(k string) string {
		if k == managedVar {
			return "OLD"
		}
		return ""
	}
	r := runCLI(t, Deps{Keychain: fakeBundle(t), Env: env}, "env")
	want := "[[ ${(t)OLD} != *readonly* ]] && builtin unset -- OLD\n[[ ${(t)ENVSEC_MANAGED_VARS} != *readonly* ]] && builtin unset -- ENVSEC_MANAGED_VARS && builtin export -- ENVSEC_MANAGED_VARS=''\n"
	if r.stdout != want || r.code != 0 {
		t.Fatalf("code=%d stdout = %q", r.code, r.stdout)
	}
}

func TestEnvRejectsBadValue(t *testing.T) {
	r := runCLI(t, Deps{Keychain: fakeBundle(t, v("BAD", "a\nb"), v("GOOD", "g"))}, "env")
	want := "[[ ${(t)BAD} != *readonly* ]] && builtin unset -- BAD\n" +
		"[[ ${(t)GOOD} != *readonly* ]] && builtin unset -- GOOD && builtin export -- GOOD='g'\n" +
		"[[ ${(t)ENVSEC_MANAGED_VARS} != *readonly* ]] && builtin unset -- ENVSEC_MANAGED_VARS && builtin export -- ENVSEC_MANAGED_VARS='GOOD'\n"
	if r.stdout != want {
		t.Fatalf("stdout = %q\nwant %q", r.stdout, want)
	}
	if r.code != 1 {
		t.Fatalf("code=%d", r.code)
	}
	if r.stderr != "envsec: rejected 1 var(s): BAD (value contains control byte 0x0a)\n" {
		t.Fatalf("stderr = %q", r.stderr)
	}
	if strings.Contains(r.stderr, "a\nb") {
		t.Fatal("stderr leaked the value")
	}
}

func TestEnvRejectsDenylisted(t *testing.T) {
	r := runCLI(t, Deps{Keychain: fakeBundle(t, v("PATH", "/evil"), v("LC_ALL", "C"), v("OK", "1"))}, "env")
	want := "[[ ${(t)LC_ALL} != *readonly* ]] && builtin unset -- LC_ALL\n" +
		"[[ ${(t)OK} != *readonly* ]] && builtin unset -- OK && builtin export -- OK='1'\n" +
		"[[ ${(t)PATH} != *readonly* ]] && builtin unset -- PATH\n" +
		"[[ ${(t)ENVSEC_MANAGED_VARS} != *readonly* ]] && builtin unset -- ENVSEC_MANAGED_VARS && builtin export -- ENVSEC_MANAGED_VARS='OK'\n"
	if r.stdout != want {
		t.Fatalf("stdout = %q\nwant %q", r.stdout, want)
	}
	if r.code != 1 || r.stderr != "envsec: rejected 2 var(s): LC_ALL (denylisted), PATH (denylisted)\n" {
		t.Fatalf("code=%d stderr=%q", r.code, r.stderr)
	}
}

func TestEnvRejectsInvalidNameWithoutUnset(t *testing.T) {
	r := runCLI(t, Deps{Keychain: fakeBundle(t, v("bad name", "x"), v("OK", "1"))}, "env")
	want := "[[ ${(t)OK} != *readonly* ]] && builtin unset -- OK && builtin export -- OK='1'\n[[ ${(t)ENVSEC_MANAGED_VARS} != *readonly* ]] && builtin unset -- ENVSEC_MANAGED_VARS && builtin export -- ENVSEC_MANAGED_VARS='OK'\n"
	if r.stdout != want || r.code != 1 {
		t.Fatalf("code=%d stdout = %q", r.code, r.stdout)
	}
	if r.stderr != "envsec: rejected 1 var(s): \"bad name\" (invalid name)\n" {
		t.Fatalf("stderr = %q", r.stderr)
	}
}

func TestEnvInvalidNameWarningStaysOneLine(t *testing.T) {
	r := runCLI(t, Deps{Keychain: fakeBundle(t, v("bad\nname\x1b[0m", "x"), v("OK", "1"))}, "env")
	if r.code != 1 || r.stdout != "[[ ${(t)OK} != *readonly* ]] && builtin unset -- OK && builtin export -- OK='1'\n[[ ${(t)ENVSEC_MANAGED_VARS} != *readonly* ]] && builtin unset -- ENVSEC_MANAGED_VARS && builtin export -- ENVSEC_MANAGED_VARS='OK'\n" {
		t.Fatalf("code=%d stdout=%q", r.code, r.stdout)
	}
	want := "envsec: rejected 1 var(s): \"bad\\nname\\x1b[0m\" (invalid name)\n"
	if r.stderr != want {
		t.Fatalf("stderr = %q\nwant %q", r.stderr, want)
	}
	if strings.Count(r.stderr, "\n") != 1 || strings.Contains(r.stderr, "\x1b") {
		t.Fatalf("warning is not one clean physical line: %q", r.stderr)
	}
}

func TestEnvUnreadableBundle(t *testing.T) {
	badSchema := []byte(base64.StdEncoding.EncodeToString([]byte(`{"schema":99,"vars":[]}`)))
	cases := map[string]struct {
		store      *keychain.Fake
		wantDetail string
	}{
		"missing item":   {&keychain.Fake{}, "envsec: no envsec bundle in the keychain; run envsec sync\n"},
		"unavailable":    {&keychain.Fake{ReadErr: &keychain.UnavailableError{Detail: "locked"}}, "envsec: keychain unavailable: locked; run envsec sync\n"},
		"bad base64":     {&keychain.Fake{Exists: true, Value: []byte("!!!")}, "envsec: bundle is not valid base64: illegal base64 data at input byte 0; run envsec sync\n"},
		"bad json":       {&keychain.Fake{Exists: true, Value: []byte(base64.StdEncoding.EncodeToString([]byte("{")))}, "envsec: bundle is not valid JSON: unmarshal failed; run envsec sync\n"},
		"no vars":        {&keychain.Fake{Exists: true, Value: []byte(base64.StdEncoding.EncodeToString([]byte(`{"schema":1,"generated_at":"2026-09-14T17:02:11Z"}`)))}, "envsec: bundle is not valid JSON: missing vars; run envsec sync\n"},
		"unknown schema": {&keychain.Fake{Exists: true, Value: badSchema}, "envsec: bundle schema is not supported: got 99, want 1; run envsec sync\n"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			r := runCLI(t, Deps{Keychain: tc.store}, "env")
			if r.stdout != "" {
				t.Fatalf("stdout = %q, want empty", r.stdout)
			}
			if r.code != 4 {
				t.Fatalf("code=%d err=%v", r.code, r.err)
			}
			if strings.Count(r.stderr, "\n") != 1 || !strings.HasPrefix(r.stderr, "envsec: ") || !strings.HasSuffix(r.stderr, "; run envsec sync\n") {
				t.Fatalf("stderr = %q", r.stderr)
			}
			if strings.HasPrefix(r.stderr, "{") {
				t.Fatalf("stderr is JSON, want a warning line: %q", r.stderr)
			}
			if tc.wantDetail != "" && r.stderr != tc.wantDetail {
				t.Fatalf("stderr = %q, want %q", r.stderr, tc.wantDetail)
			}
		})
	}
}

func TestEnvNeverCallsOnePass(t *testing.T) {
	op := &onepass.Fake{}
	runCLI(t, Deps{Keychain: fakeBundle(t, v("A", "1")), OnePass: op}, "env")
	if len(op.Calls) != 0 {
		t.Fatalf("op calls: %+v", op.Calls)
	}
}

func TestEnvZshRoundTrip(t *testing.T) {
	if _, err := os.Stat("/bin/zsh"); err != nil {
		t.Skip("/bin/zsh not present")
	}
	value := "it's $HOME `id` \\ \"q\" 日本語 ✓"
	env := func(k string) string {
		if k == managedVar {
			return "STALE"
		}
		return ""
	}
	r := runCLI(t, Deps{Keychain: fakeBundle(t, v("TRICKY", value), v("PLAIN", "p")), Env: env}, "env")
	if r.code != 0 {
		t.Fatalf("code=%d stderr=%q", r.code, r.stderr)
	}
	script := filepath.Join(t.TempDir(), "env.zsh")
	if err := os.WriteFile(script, []byte(r.stdout), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/zsh", "-f", "-c",
		`eval "$(cat "$1")"; printf '%s\n' "$TRICKY" "$PLAIN" "$ENVSEC_MANAGED_VARS" "${+STALE}"`, "zsh", script)
	cmd.WaitDelay = 2 * time.Second
	cmd.Env = []string{"PATH=/bin:/usr/bin", "STALE=inherited"}
	got, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("zsh: %v\n%s", err, got)
	}
	want := value + "\np\nPLAIN TRICKY\n0\n"
	if string(got) != want {
		t.Fatalf("zsh printed %q\nwant        %q", got, want)
	}
}

// TestEnvZshReadonlyTargetDoesNotAbortEval evals a full env output in a shell
// where one target (RO) and one stale inherited name (STALE_RO) are readonly.
// Every other line must still run: the other vars export, the stale scalar
// is unset, and the sentinel lands. envsec cannot see the caller's shell, so
// RO is silently skipped and still listed in ENVSEC_MANAGED_VARS; a later run
// emits a guarded unset for it, which is a no-op.
func TestEnvZshReadonlyTargetDoesNotAbortEval(t *testing.T) {
	if _, err := os.Stat("/bin/zsh"); err != nil {
		t.Skip("/bin/zsh not present")
	}
	env := func(k string) string {
		if k == managedVar {
			return "STALE STALE_RO"
		}
		return ""
	}
	r := runCLI(t, Deps{Keychain: fakeBundle(t, v("ALPHA", "a"), v("RO", "path[$(touch /nonexistent/marker)]"), v("ZED", "z")), Env: env}, "env")
	if r.code != 0 || r.stderr != "" {
		t.Fatalf("code=%d stderr=%q", r.code, r.stderr)
	}
	script := filepath.Join(t.TempDir(), "env.zsh")
	if err := os.WriteFile(script, []byte(r.stdout), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/zsh", "-f", "-c",
		`typeset -r RO=orig; typeset -r STALE_RO=keep; eval "$(cat "$1")"; rc=$?; printf '%s\n' "$rc" "$ALPHA" "$RO" "$ZED" "$STALE_RO" "${+STALE}" "$ENVSEC_MANAGED_VARS"`, "zsh", script)
	cmd.WaitDelay = 2 * time.Second
	cmd.Env = []string{"PATH=/bin:/usr/bin", "STALE=inherited"}
	got, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("zsh: %v\n%s", err, got)
	}
	want := "0\na\norig\nz\nkeep\n0\nALPHA RO ZED\n"
	if string(got) != want {
		t.Fatalf("zsh printed %q\nwant        %q", got, want)
	}
}

func TestList(t *testing.T) {
	r := runCLI(t, Deps{Keychain: fakeBundle(t, v("ZED", "z"), v("ALPHA", "a"))}, "list")
	want := `{"var":"ALPHA","account":"my.1password.com","item_id":"item-alpha","field_id":"field-alpha"}` + "\n" +
		`{"var":"ZED","account":"my.1password.com","item_id":"item-zed","field_id":"field-zed"}` + "\n" +
		`{"_meta":{"has_more":false,"generated_at":"2026-09-14T17:02:11Z"}}` + "\n"
	if r.stdout != want {
		t.Fatalf("stdout = %q\nwant %q", r.stdout, want)
	}
	if r.code != 0 || r.stderr != "" {
		t.Fatalf("code=%d stderr=%q", r.code, r.stderr)
	}
	if strings.Contains(r.stdout, `"z"`) || strings.Contains(r.stdout, `"a"`) {
		t.Fatal("list printed a value")
	}
}

func TestListUnreadable(t *testing.T) {
	cases := map[string]struct {
		store *keychain.Fake
		want  string
	}{
		"missing":     {&keychain.Fake{}, `{"error":"bundle_missing","detail":"no envsec bundle in the keychain","hint":"envsec sync"}` + "\n"},
		"unavailable": {&keychain.Fake{ReadErr: &keychain.UnavailableError{Detail: "locked"}}, `{"error":"keychain_unavailable","detail":"keychain unavailable: locked","hint":"envsec sync"}` + "\n"},
		"bad base64":  {&keychain.Fake{Exists: true, Value: []byte("!!!")}, `{"error":"bundle_invalid","detail":"bundle is not valid base64: illegal base64 data at input byte 0","hint":"envsec sync"}` + "\n"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			r := runCLI(t, Deps{Keychain: tc.store}, "list")
			if r.stdout != "" || r.code != 4 || r.stderr != tc.want {
				t.Fatalf("code=%d stdout=%q stderr=%q\nwant stderr %q", r.code, r.stdout, r.stderr, tc.want)
			}
		})
	}
}

func TestKeychainFlagReachesStore(t *testing.T) {
	var got keychain.Options
	orig := newKeychain
	newKeychain = func(o keychain.Options) keychain.Store {
		got = o
		return &keychain.Fake{}
	}
	t.Cleanup(func() { newKeychain = orig })

	var out, errb bytes.Buffer
	_ = Run([]string{"--keychain", "/tmp/test.keychain-db", "--timeout", "3s", "list"}, &out, &errb)
	if got.KeychainPath != "/tmp/test.keychain-db" || got.Timeout != 3*time.Second {
		t.Fatalf("options = %+v", got)
	}
}

func TestVerboseFlagReachesOnePass(t *testing.T) {
	var got onepass.Options
	orig := newOnePass
	newOnePass = func(o onepass.Options) onepass.Client {
		got = o
		return &onepass.Fake{}
	}
	t.Cleanup(func() { newOnePass = orig })

	var out, errb bytes.Buffer
	_ = Run([]string{"--verbose", "--timeout", "3s", "check"}, &out, &errb)
	if !got.Verbose || got.Timeout != 3*time.Second || got.Stderr != &errb {
		t.Fatalf("options = %+v", got)
	}
	_ = Run([]string{"check"}, &out, &errb)
	if got.Verbose {
		t.Fatal("verbose set without --verbose")
	}
}

func TestExitCode(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
		code string
	}{
		{"nil", nil, 0, ""},
		{"generic", errors.New("boom"), 1, "failed"},
		{"auth", &onepass.AuthError{Account: onepass.Account{URL: "my.1password.com"}, Detail: "locked"}, 2, "onepassword_unauthorized"},
		{"unavailable", &keychain.UnavailableError{Detail: "x"}, 4, "keychain_unavailable"},
		{"not found", keychain.ErrNotFound, 4, "bundle_missing"},
		{"bad base64", bundle.ErrBadBase64, 4, "bundle_invalid"},
		{"bad json", bundle.ErrBadJSON, 4, "bundle_invalid"},
		{"schema", bundle.ErrUnknownSchema, 4, "bundle_invalid"},
		{"exit error", &ExitError{Code: 7, Err: "custom"}, 7, "custom"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.err == nil {
				if ExitCode(nil) != 0 {
					t.Fatal("nil must be 0")
				}
				return
			}
			e := asExit(tc.err)
			if e.Code != tc.want || e.Err != tc.code || ExitCode(e) != tc.want {
				t.Fatalf("got code=%d err=%q, want %d %q", e.Code, e.Err, tc.want, tc.code)
			}
		})
	}
	if ExitCode(errors.New("plain")) != 1 {
		t.Fatal("plain error must map to 1")
	}
	if e := asExit(&onepass.AuthError{Account: onepass.Account{URL: "my.1password.com"}}); e.Hint != "op signin --account my.1password.com" {
		t.Fatalf("hint = %q", e.Hint)
	}
}
