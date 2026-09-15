package cli

import (
	"strings"
	"testing"

	"github.com/tammersaleh/envsec/internal/keychain"
	"github.com/tammersaleh/envsec/internal/onepass"
)

// runCheck runs `envsec check` and fails the test if anything was written or
// any output stream leaks a value.
func runCheck(t *testing.T, kc *keychain.Fake, op onepass.Client, args ...string) result {
	t.Helper()
	r := runCLI(t, Deps{Keychain: kc, OnePass: op}, append([]string{"check"}, args...)...)
	noValues(t, r)
	if kc.Writes != 0 {
		t.Fatalf("check wrote to the keychain %d time(s)", kc.Writes)
	}
	return r
}

func TestCheckAllOK(t *testing.T) {
	kc := fakeBundle(t, sv("ALPHA", "a"), sv("ZED", "z"))
	r := runCheck(t, kc, fakeOp(varItem("ZED", "z"), varItem("ALPHA", "a")))
	want := `{"var":"ALPHA","account":"my.1password.com","status":"ok"}` + "\n" +
		`{"var":"ZED","account":"my.1password.com","status":"ok"}` + "\n" + trailerOK
	if r.code != 0 || r.stdout != want || r.stderr != "" {
		t.Fatalf("code=%d stdout=%q stderr=%q", r.code, r.stdout, r.stderr)
	}
}

func TestCheckStatuses(t *testing.T) {
	kc := fakeBundle(t, sv("SAME", "s"), sv("DIFF", "old"), sv("STALE", "x"))
	r := runCheck(t, kc, fakeOp(varItem("SAME", "s"), varItem("DIFF", "new"), varItem("NEW", "n")))
	want := `{"var":"DIFF","account":"my.1password.com","status":"different"}` + "\n" +
		`{"var":"NEW","account":"my.1password.com","status":"missing"}` + "\n" +
		`{"var":"SAME","account":"my.1password.com","status":"ok"}` + "\n" +
		`{"var":"STALE","account":"my.1password.com","status":"stale"}` + "\n" +
		`{"_meta":{"has_more":false,"error_count":3}}` + "\n"
	if r.code != 1 || r.stdout != want || r.stderr != "" {
		t.Fatalf("code=%d stdout=%q stderr=%q\nwant %q", r.code, r.stdout, r.stderr, want)
	}
}

func TestCheckProvenanceChangeIsDifferent(t *testing.T) {
	kc := fakeBundle(t, sv("ALPHA", "a"))
	moved := varItem("ALPHA", "a")
	moved.ID = "item-alpha-moved"
	r := runCheck(t, kc, fakeOp(moved))
	want := `{"var":"ALPHA","account":"my.1password.com","status":"different"}` + "\n" +
		`{"_meta":{"has_more":false,"error_count":1}}` + "\n"
	if r.code != 1 || r.stdout != want {
		t.Fatalf("code=%d stdout=%q", r.code, r.stdout)
	}
}

func TestCheckConflictRows(t *testing.T) {
	kc := fakeBundle(t, sv("TOKEN", "one"), sv("ALPHA", "a"))
	op := twoAccountOp()
	op.Items[acct1.AccountUUID] = append(op.Items[acct1.AccountUUID], varItem("ALPHA", "a"))
	r := runCheck(t, kc, op)
	// A conflicted var yields exactly one row: the bundle copy is not
	// reported stale, because there is no single truth to compare against.
	want := `{"var":"ALPHA","account":"my.1password.com","status":"ok"}` + "\n" +
		`{"var":"TOKEN","account":"","status":"conflict","detail":"conflict: TOKEN is defined by item item-token (my.1password.com) and item item-token2 (other.1password.com)"}` + "\n" +
		`{"_meta":{"has_more":false,"error_count":1}}` + "\n"
	if r.code != 1 || r.stdout != want {
		t.Fatalf("code=%d stdout=%q\nwant %q", r.code, r.stdout, want)
	}
}

func TestCheckSelectionErrorRow(t *testing.T) {
	kc := fakeBundle(t, sv("ALPHA", "a"))
	r := runCheck(t, kc, fakeOp(varItem("ALPHA", "a"), varItem("PATH", "p")))
	want := `{"var":"ALPHA","account":"my.1password.com","status":"ok"}` + "\n" +
		`{"var":"PATH","account":"my.1password.com","status":"error","detail":"item \"Title PATH\" (item-path): label PATH is denylisted"}` + "\n" +
		`{"_meta":{"has_more":false,"error_count":1}}` + "\n"
	if r.code != 1 || r.stdout != want {
		t.Fatalf("code=%d stdout=%q\nwant %q", r.code, r.stdout, want)
	}
}

func TestCheckCachedVarWithEmptySourceIsErrorNotStale(t *testing.T) {
	// The bundle holds ALPHA; in 1Password its field is now empty. That is a
	// source validation failure: one error row, and no stale row for the
	// cached copy.
	kc := fakeBundle(t, sv("ALPHA", "a"))
	empty := opItem("item-alpha", "Title ALPHA", onepass.Field{ID: "field-alpha", Type: "CONCEALED", Label: "ALPHA"})
	r := runCheck(t, kc, fakeOp(empty))
	want := `{"var":"ALPHA","account":"my.1password.com","status":"error","detail":"item \"Title ALPHA\" (item-alpha): ALPHA is empty"}` + "\n" +
		`{"_meta":{"has_more":false,"error_count":1}}` + "\n"
	if r.code != 1 || r.stdout != want {
		t.Fatalf("code=%d stdout=%q\nwant %q", r.code, r.stdout, want)
	}
}

func TestCheckSameLabelTwiceInOneItemIsOneConflictRow(t *testing.T) {
	kc := fakeBundle(t, sv("TOKEN", "one"))
	twice := opItem("item-twice", "Twice", secret("TOKEN", "one"), onepass.Field{ID: "field-token-2", Type: "CONCEALED", Label: "TOKEN", Value: marker + "-two"})
	r := runCheck(t, kc, fakeOp(twice))
	want := `{"var":"TOKEN","account":"","status":"conflict","detail":"conflict: TOKEN is defined by item item-twice field field-token (my.1password.com) and item item-twice field field-token-2 (my.1password.com)"}` + "\n" +
		`{"_meta":{"has_more":false,"error_count":1}}` + "\n"
	if r.code != 1 || r.stdout != want {
		t.Fatalf("code=%d stdout=%q\nwant %q", r.code, r.stdout, want)
	}
}

func TestCheckValidPlusInvalidSameNameIsOneErrorRow(t *testing.T) {
	// One item yields TOKEN, another has TOKEN with an empty value. Only one
	// source, so no conflict; the name is excluded from the comparison and
	// reported once as an error, never also as ok or missing.
	kc := fakeBundle(t, sv("TOKEN", "one"))
	empty := opItem("item-empty", "Empty", onepass.Field{ID: "field-token-e", Type: "CONCEALED", Label: "TOKEN"})
	r := runCheck(t, kc, fakeOp(varItem("TOKEN", "one"), empty))
	want := `{"var":"TOKEN","account":"my.1password.com","status":"error","detail":"item \"Empty\" (item-empty): TOKEN is empty"}` + "\n" +
		`{"_meta":{"has_more":false,"error_count":1}}` + "\n"
	if r.code != 1 || r.stdout != want {
		t.Fatalf("code=%d stdout=%q\nwant %q", r.code, r.stdout, want)
	}
}

func TestCheckRepeatedInvalidLabelIsOneRow(t *testing.T) {
	kc := fakeBundle(t, sv("ALPHA", "a"))
	second := varItem("PATH", "p2")
	second.ID = "item-path2"
	second.Title = "Second PATH"
	r := runCheck(t, kc, fakeOp(varItem("ALPHA", "a"), varItem("PATH", "p"), second))
	want := `{"var":"ALPHA","account":"my.1password.com","status":"ok"}` + "\n" +
		`{"var":"PATH","account":"my.1password.com","status":"error","detail":"item \"Title PATH\" (item-path): label PATH is denylisted; item \"Second PATH\" (item-path2): label PATH is denylisted"}` + "\n" +
		`{"_meta":{"has_more":false,"error_count":1}}` + "\n"
	if r.code != 1 || r.stdout != want {
		t.Fatalf("code=%d stdout=%q\nwant %q", r.code, r.stdout, want)
	}
}

func TestCheckConflictWinsOverError(t *testing.T) {
	// TOKEN is valid in two items (conflict) and empty in a third (error):
	// one row, status conflict, both details.
	kc := fakeBundle(t, sv("TOKEN", "one"))
	op := twoAccountOp()
	empty := opItem("item-empty", "Empty", onepass.Field{ID: "field-token-e", Type: "CONCEALED", Label: "TOKEN"})
	op.Items[acct1.AccountUUID] = append(op.Items[acct1.AccountUUID], empty)
	r := runCheck(t, kc, op)
	want := `{"var":"TOKEN","account":"","status":"conflict","detail":"conflict: TOKEN is defined by item item-token (my.1password.com) and item item-token2 (other.1password.com); item \"Empty\" (item-empty): TOKEN is empty"}` + "\n" +
		`{"_meta":{"has_more":false,"error_count":1}}` + "\n"
	if r.code != 1 || r.stdout != want {
		t.Fatalf("code=%d stdout=%q\nwant %q", r.code, r.stdout, want)
	}
}

func TestCheckBundleMissingIsAllMissing(t *testing.T) {
	kc := &keychain.Fake{}
	r := runCheck(t, kc, fakeOp(varItem("ALPHA", "a")))
	want := `{"var":"ALPHA","account":"my.1password.com","status":"missing"}` + "\n" +
		`{"_meta":{"has_more":false,"error_count":1}}` + "\n"
	if r.code != 1 || r.stdout != want || r.stderr != "" {
		t.Fatalf("code=%d stdout=%q stderr=%q", r.code, r.stdout, r.stderr)
	}
}

func TestCheckKeychainUnavailable(t *testing.T) {
	kc := &keychain.Fake{ReadErr: &keychain.UnavailableError{Detail: "locked"}}
	r := runCheck(t, kc, fakeOp(varItem("ALPHA", "a")))
	if r.code != 4 || r.stdout != "" || !strings.Contains(r.stderr, `"error":"keychain_unavailable"`) {
		t.Fatalf("code=%d stdout=%q stderr=%q", r.code, r.stdout, r.stderr)
	}
}

func TestCheckAuthErrorIsExit2(t *testing.T) {
	kc := fakeBundle(t, sv("ALPHA", "a"))
	op := fakeOp(varItem("ALPHA", "a"))
	op.Errs.ListTagged = &onepass.AuthError{Account: acct1, Detail: "locked"}
	r := runCheck(t, kc, op)
	want := `{"error":"onepassword_unauthorized","detail":"check aborted: account my.1password.com could not be authorized: locked; keychain cache unchanged; unlock 1Password and rerun","hint":"op signin --account my.1password.com"}` + "\n"
	if r.code != 2 || r.stdout != "" || r.stderr != want {
		t.Fatalf("code=%d stdout=%q stderr=%q", r.code, r.stdout, r.stderr)
	}
}

func TestCheckZeroAccountsIsExit2(t *testing.T) {
	kc := fakeBundle(t, sv("ALPHA", "a"))
	r := runCheck(t, kc, &onepass.Fake{})
	want := `{"error":"onepassword_unauthorized","detail":"check aborted: 1Password could not be authorized: no 1Password accounts are signed in; keychain cache unchanged; unlock 1Password and rerun","hint":"op signin"}` + "\n"
	if r.code != 2 || r.stdout != "" || r.stderr != want {
		t.Fatalf("code=%d stdout=%q stderr=%q", r.code, r.stdout, r.stderr)
	}
}

func TestCheckOpTimeoutIsExit2(t *testing.T) {
	kc := fakeBundle(t, sv("ALPHA", "a"))
	op := fakeOp(varItem("ALPHA", "a"))
	op.Errs.GetItem = &onepass.AuthError{Account: acct1, Detail: "op timed out after 60s; a Touch ID or unlock prompt was probably unanswered", Err: onepass.ErrTimeout}
	r := runCheck(t, kc, op)
	if r.code != 2 || r.stdout != "" || !strings.Contains(r.stderr, `"error":"onepassword_unauthorized"`) ||
		!strings.Contains(r.stderr, "a Touch ID or unlock prompt was probably unanswered") {
		t.Fatalf("code=%d stdout=%q stderr=%q", r.code, r.stdout, r.stderr)
	}
}

func TestCheckDoesNotTakeSyncLock(t *testing.T) {
	useTempLock(t)
	release, err := acquireLock()
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	kc := fakeBundle(t, sv("ALPHA", "a"))
	r := runCheck(t, kc, fakeOp(varItem("ALPHA", "a")))
	if r.code != 0 {
		t.Fatalf("code=%d stderr=%q", r.code, r.stderr)
	}
}
