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
	want := `{"var":"TOKEN","status":"conflict","detail":"conflict: TOKEN is defined by item item-token (my.1password.com) and item item-token2 (other.1password.com)"}` + "\n" +
		`{"var":"ALPHA","account":"my.1password.com","status":"ok"}` + "\n" +
		`{"var":"TOKEN","account":"my.1password.com","status":"stale"}` + "\n" +
		`{"_meta":{"has_more":false,"error_count":2}}` + "\n"
	if r.code != 1 || r.stdout != want {
		t.Fatalf("code=%d stdout=%q\nwant %q", r.code, r.stdout, want)
	}
}

func TestCheckSelectionErrorRow(t *testing.T) {
	kc := fakeBundle(t, sv("ALPHA", "a"))
	r := runCheck(t, kc, fakeOp(varItem("ALPHA", "a"), varItem("PATH", "p")))
	want := `{"var":"","status":"error","detail":"item \"Title PATH\" (item-path): label PATH is denylisted"}` + "\n" +
		`{"var":"ALPHA","account":"my.1password.com","status":"ok"}` + "\n" +
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
	want := `{"error":"onepassword_unauthorized","detail":"check aborted: account my.1password.com could not be authorized; keychain cache unchanged; unlock 1Password and rerun","hint":"op signin --account my.1password.com"}` + "\n"
	if r.code != 2 || r.stdout != "" || r.stderr != want {
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
