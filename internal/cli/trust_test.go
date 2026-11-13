package cli

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/tammersaleh/envsec/internal/bundle"
	"github.com/tammersaleh/envsec/internal/keychain"
	"github.com/tammersaleh/envsec/internal/onepass"
	"github.com/tammersaleh/envsec/internal/trustpicker"
)

// runTrust runs `envsec trust args...` with a fixed clock and a temp lock,
// and fails the test if any output stream leaks a value.
func runTrust(t *testing.T, deps Deps, args ...string) result {
	t.Helper()
	useTempLock(t)
	if deps.Now == nil {
		deps.Now = func() time.Time { return fixedTime }
	}
	r := runCLI(t, deps, append([]string{"trust"}, args...)...)
	noValues(t, r)
	return r
}

func revokedRow(name string) string {
	return provRow(name, "revoked", "trust revoked")
}

// fatal is the one JSON object a fatal error prints.
func fatal(code, detail, hint string) string {
	return fmt.Sprintf(`{"error":%q,"detail":%q,"hint":%q}`, code, detail, hint) + "\n"
}

func TestTrustNoArgsNoTerminal(t *testing.T) {
	kc := fakeBundle(t, sv("ALPHA", "a"))
	op := fakeOp(varItem("ALPHA", "a"))
	r := runTrust(t, Deps{Keychain: kc, OnePass: op})
	want := fatal("no_terminal", "envsec trust with no source id needs a terminal on stdin and stderr", "envsec trust <source-id>")
	if r.code != 1 || r.stdout != "" || r.stderr != want || kc.Writes != 0 {
		t.Fatalf("code=%d writes=%d stdout=%q stderr=%q", r.code, kc.Writes, r.stdout, r.stderr)
	}
	// Refused before 1Password is touched: no Touch ID prompt for nothing.
	if len(op.Calls) != 0 {
		t.Fatalf("op calls = %+v", op.Calls)
	}
}

func TestTrustPicker(t *testing.T) {
	// ALPHA is trusted and present, GONE is trusted and absent, BETA is
	// new. The user unchecks ALPHA and checks BETA.
	kc := fakeTrusting(t, []bundle.Source{src("GONE")}, sv("ALPHA", "a"))
	picker := picking(src("BETA"))
	r := runTrust(t, Deps{Keychain: kc, OnePass: fakeOp(varItem("BETA", "b"), varItem("ALPHA", "a")), Picker: picker})
	want := revokedRow("ALPHA") + row("BETA", "added") + trailerOK
	if r.stdout != want {
		t.Fatalf("stdout = %q\nwant %q", r.stdout, want)
	}
	if r.code != 0 || r.stderr != "" || kc.Writes != 1 {
		t.Fatalf("code=%d writes=%d stderr=%q", r.code, kc.Writes, r.stderr)
	}
	wantOpts := []trustpicker.Option{
		{ID: src("ALPHA").ID(), Var: "ALPHA", Account: "my.1password.com", Vault: "Private", Item: "Title ALPHA", Checked: true},
		{ID: src("BETA").ID(), Var: "BETA", Account: "my.1password.com", Vault: "Private", Item: "Title BETA"},
	}
	if picker.Calls != 1 || len(picker.Got) != 2 || picker.Got[0] != wantOpts[0] || picker.Got[1] != wantOpts[1] {
		t.Fatalf("picker calls=%d options=%+v", picker.Calls, picker.Got)
	}
	b := decodeFake(t, kc)
	if len(b.Vars) != 1 || b.Vars[0] != sv("BETA", "b") {
		t.Fatalf("bundle has %d vars or the wrong one", len(b.Vars))
	}
	// The absent source is not shown and stays trusted.
	wantTrusted(t, kc, src("BETA"), src("GONE"))
}

func TestTrustPickerKeepsCheckedAndReportsTheRest(t *testing.T) {
	kc := fakeBundle(t, sv("ALPHA", "a"))
	picker := picking(src("ALPHA"))
	r := runTrust(t, Deps{Keychain: kc, OnePass: fakeOp(varItem("ALPHA", "a"), varItem("BETA", "b")), Picker: picker})
	want := row("ALPHA", "unchanged") + untrustedRow("BETA") + trailer(1)
	if r.stdout != want || r.code != 1 || r.stderr != warning("BETA") || kc.Writes != 1 {
		t.Fatalf("code=%d writes=%d stderr=%q stdout=%q\nwant %q", r.code, kc.Writes, r.stderr, r.stdout, want)
	}
	wantTrusted(t, kc, src("ALPHA"))
}

func TestTrustPickerCancelled(t *testing.T) {
	kc := fakeBundle(t, sv("ALPHA", "a"))
	before := string(kc.Value)
	picker := &trustpicker.Fake{IsAvailable: true, Err: trustpicker.ErrCancelled}
	r := runTrust(t, Deps{Keychain: kc, OnePass: fakeOp(varItem("ALPHA", "a"), varItem("BETA", "b")), Picker: picker})
	want := fatal("trust_cancelled", "the trust picker was cancelled; nothing was written", "envsec trust")
	if r.code != 1 || r.stdout != "" || r.stderr != want || kc.Writes != 0 || string(kc.Value) != before {
		t.Fatalf("code=%d writes=%d stdout=%q stderr=%q", r.code, kc.Writes, r.stdout, r.stderr)
	}
}

func TestTrustIDs(t *testing.T) {
	kc := fakeBundle(t, sv("ALPHA", "a"))
	picker := &trustpicker.Fake{IsAvailable: true}
	op := fakeOp(varItem("ALPHA", "a"), varItem("BETA", "b"), varItem("GAMMA", "g"))
	r := runTrust(t, Deps{Keychain: kc, OnePass: op, Picker: picker}, src("BETA").ID(), src("GAMMA").ID())
	want := row("ALPHA", "unchanged") + row("BETA", "added") + row("GAMMA", "added") + trailerOK
	if r.stdout != want || r.code != 0 || r.stderr != "" || kc.Writes != 1 {
		t.Fatalf("code=%d writes=%d stderr=%q stdout=%q\nwant %q", r.code, kc.Writes, r.stderr, r.stdout, want)
	}
	if picker.Calls != 0 {
		t.Fatalf("picker calls = %d", picker.Calls)
	}
	b := decodeFake(t, kc)
	if len(b.Vars) != 3 || b.Vars[1] != sv("BETA", "b") || b.Vars[2] != sv("GAMMA", "g") {
		t.Fatalf("bundle has %d vars or the wrong ones", len(b.Vars))
	}
	wantTrusted(t, kc, src("ALPHA"), src("BETA"), src("GAMMA"))
}

func TestTrustIDsRevokeNothingAndReportOtherUntrusted(t *testing.T) {
	kc := fakeTrusting(t, []bundle.Source{src("GONE")}, sv("ALPHA", "a"))
	op := fakeOp(varItem("ALPHA", "a"), varItem("BETA", "b"), varItem("GAMMA", "g"))
	r := runTrust(t, Deps{Keychain: kc, OnePass: op}, src("BETA").ID())
	want := row("ALPHA", "unchanged") + row("BETA", "added") + untrustedRow("GAMMA") + trailer(1)
	if r.stdout != want || r.code != 1 || r.stderr != warning("GAMMA") || kc.Writes != 1 {
		t.Fatalf("code=%d writes=%d stderr=%q stdout=%q\nwant %q", r.code, kc.Writes, r.stderr, r.stdout, want)
	}
	wantTrusted(t, kc, src("ALPHA"), src("BETA"), src("GONE"))
}

func TestTrustIDOnLegacyBundle(t *testing.T) {
	kc := legacyBundle(t, sv("ALPHA", "a"))
	r := runTrust(t, Deps{Keychain: kc, OnePass: fakeOp(varItem("ALPHA", "a"))}, src("ALPHA").ID())
	if r.stdout != row("ALPHA", "unchanged")+trailerOK || r.code != 0 || kc.Writes != 1 {
		t.Fatalf("code=%d writes=%d stdout=%q stderr=%q", r.code, kc.Writes, r.stdout, r.stderr)
	}
	if b := decodeFake(t, kc); b.Schema != bundle.Schema || len(b.Vars) != 1 || b.Vars[0] != sv("ALPHA", "a") {
		t.Fatalf("bundle schema=%d vars=%d", b.Schema, len(b.Vars))
	}
}

// TestTrustIDsRefused: all ids apply or none. Every case writes nothing.
func TestTrustIDsRefused(t *testing.T) {
	alpha, beta := src("ALPHA").ID(), src("BETA").ID()
	path := src("PATH").ID()
	nope := src("NOPE").ID()
	planted := src2("item-token2", "TOKEN")
	const wantShape = "src_ plus 26 characters of a-z and 2-7"
	cases := map[string]struct {
		args   []string
		want   string
		opUsed bool
	}{
		"unknown id": {[]string{nope},
			fatal("unknown_source_id", "no valid source in 1Password has this id: "+nope, "envsec check"), true},
		"valid plus typo": {[]string{beta, nope},
			fatal("unknown_source_id", "no valid source in 1Password has this id: "+nope, "envsec check"), true},
		"repeated id": {[]string{beta, beta},
			fatal("duplicate_source_id", "source id given more than once: "+beta, "envsec trust <source-id>"), false},
		"malformed id": {[]string{beta, "src_UPPER"},
			fatal("invalid_source_id", "argument 2 is not a source id ("+wantShape+")", "envsec check"), false},
		"hostile id": {[]string{"src_\x1b[2J\nx" + marker},
			fatal("invalid_source_id", "argument 1 is not a source id ("+wantShape+")", "envsec check"), false},
		"id of an invalid source": {[]string{path},
			fatal("source_invalid", "source cannot be trusted: "+path+" (label PATH is denylisted)", "fix the field in 1Password"), true},
		"conflict with a trusted source": {[]string{planted.ID()},
			fatal("trust_conflict", "TOKEN would have more than one trusted source: "+src("TOKEN").ID()+", "+planted.ID(), "envsec trust --revoke <source-id>"), true},
		"revoke with no id": {[]string{"--revoke"},
			fatal("usage", "--revoke needs at least one source id", "envsec trust --revoke <source-id>"), false},
		"revoke an id that is not trusted": {[]string{"--revoke", beta},
			fatal("unknown_source_id", "no trusted source has this id: "+beta, "envsec list"), true},
		"revoke valid plus unknown": {[]string{"--revoke", alpha, nope},
			fatal("unknown_source_id", "no trusted source has this id: "+nope, "envsec list"), true},
		"revoke repeated": {[]string{"--revoke", alpha, alpha},
			fatal("duplicate_source_id", "source id given more than once: "+alpha, "envsec trust <source-id>"), false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			kc := fakeBundle(t, sv("ALPHA", "a"), sv("TOKEN", "one"))
			before := string(kc.Value)
			op := twoAccountOp()
			op.Items[acct1.AccountUUID] = append(op.Items[acct1.AccountUUID], varItem("ALPHA", "a"), varItem("BETA", "b"), varItem("PATH", "p"))
			picker := &trustpicker.Fake{IsAvailable: true}
			r := runTrust(t, Deps{Keychain: kc, OnePass: op, Picker: picker}, tc.args...)
			if r.stderr != tc.want {
				t.Fatalf("stderr = %q\nwant     %q", r.stderr, tc.want)
			}
			if r.code != 1 || r.stdout != "" || kc.Writes != 0 || string(kc.Value) != before || picker.Calls != 0 {
				t.Fatalf("code=%d writes=%d picker=%d stdout=%q", r.code, kc.Writes, picker.Calls, r.stdout)
			}
			if tc.opUsed != (len(op.Calls) > 0) {
				t.Fatalf("op calls = %d, want used=%v", len(op.Calls), tc.opUsed)
			}
			if strings.Contains(r.stderr, "\x1b") || strings.Count(r.stderr, "\n") != 1 {
				t.Fatalf("stderr is not one clean line: %q", r.stderr)
			}
		})
	}
}

func TestTrustTwoIDsWithTheSameNameConflict(t *testing.T) {
	kc := fakeBundle(t, sv("ALPHA", "a"))
	op := twoAccountOp()
	planted := src2("item-token2", "TOKEN")
	r := runTrust(t, Deps{Keychain: kc, OnePass: op}, src("TOKEN").ID(), planted.ID())
	want := fatal("trust_conflict", "TOKEN would have more than one trusted source: "+src("TOKEN").ID()+", "+planted.ID(), "envsec trust --revoke <source-id>")
	if r.code != 1 || r.stdout != "" || r.stderr != want || kc.Writes != 0 {
		t.Fatalf("code=%d writes=%d stdout=%q stderr=%q", r.code, kc.Writes, r.stdout, r.stderr)
	}
}

// TestTrustIDAllowedBesideAnAbsentSourceOfTheSameName: only sources present
// in this resolution can conflict.
func TestTrustIDAllowedBesideAnAbsentSourceOfTheSameName(t *testing.T) {
	absent := src("TOKEN")
	absent.ItemID = "item-token-old"
	kc := fakeTrusting(t, []bundle.Source{absent})
	r := runTrust(t, Deps{Keychain: kc, OnePass: fakeOp(varItem("TOKEN", "one"))}, src("TOKEN").ID())
	if r.code != 0 || r.stdout != row("TOKEN", "added")+trailerOK || kc.Writes != 1 {
		t.Fatalf("code=%d writes=%d stdout=%q stderr=%q", r.code, kc.Writes, r.stdout, r.stderr)
	}
	wantTrusted(t, kc, src("TOKEN"), absent)
}

func TestTrustRevokePresentSource(t *testing.T) {
	kc := fakeBundle(t, sv("ALPHA", "a"), sv("BETA", "b"))
	picker := &trustpicker.Fake{IsAvailable: true}
	r := runTrust(t, Deps{Keychain: kc, OnePass: fakeOp(varItem("ALPHA", "a"), varItem("BETA", "b")), Picker: picker}, "--revoke", src("ALPHA").ID())
	want := revokedRow("ALPHA") + row("BETA", "unchanged") + trailerOK
	if r.stdout != want {
		t.Fatalf("stdout = %q\nwant %q", r.stdout, want)
	}
	// A source revoked in this run is not an error and not untrusted.
	if r.code != 0 || r.stderr != "" || kc.Writes != 1 || picker.Calls != 0 {
		t.Fatalf("code=%d writes=%d picker=%d stderr=%q", r.code, kc.Writes, picker.Calls, r.stderr)
	}
	if b := decodeFake(t, kc); len(b.Vars) != 1 || b.Vars[0] != sv("BETA", "b") {
		t.Fatalf("bundle has %d vars or the wrong one", len(b.Vars))
	}
	wantTrusted(t, kc, src("BETA"))

	// The next sync sees it as any other untrusted source.
	r = runSync(t, Deps{Keychain: kc, OnePass: fakeOp(varItem("ALPHA", "a"), varItem("BETA", "b"))})
	if r.code != 1 || r.stdout != untrustedRow("ALPHA")+row("BETA", "unchanged")+trailer(1) {
		t.Fatalf("sync after revoke: code=%d stdout=%q", r.code, r.stdout)
	}
}

func TestTrustRevokeAbsentSource(t *testing.T) {
	kc := fakeTrusting(t, []bundle.Source{src("GONE")}, sv("ALPHA", "a"))
	r := runTrust(t, Deps{Keychain: kc, OnePass: fakeOp(varItem("ALPHA", "a"))}, "--revoke", src("GONE").ID())
	// Absent from 1Password: only the stored tuple is known.
	want := row("ALPHA", "unchanged") +
		`{"var":"GONE","account":"","vault_id":"vault","item_id":"item-gone","field_id":"field-gone","source_id":"` + src("GONE").ID() + `","status":"revoked","detail":"trust revoked"}` + "\n" + trailerOK
	if r.stdout != want || r.code != 0 || r.stderr != "" || kc.Writes != 1 {
		t.Fatalf("code=%d writes=%d stderr=%q stdout=%q\nwant %q", r.code, kc.Writes, r.stderr, r.stdout, want)
	}
	wantTrusted(t, kc, src("ALPHA"))
}

func TestTrustRevokeStillReportsOtherUntrustedSources(t *testing.T) {
	kc := fakeBundle(t, sv("ALPHA", "a"), sv("BETA", "b"))
	op := fakeOp(varItem("ALPHA", "a"), varItem("BETA", "b"), varItem("NEW", "n"))
	r := runTrust(t, Deps{Keychain: kc, OnePass: op}, "--revoke", src("ALPHA").ID())
	want := revokedRow("ALPHA") + row("BETA", "unchanged") + untrustedRow("NEW") + trailer(1)
	if r.stdout != want || r.code != 1 || r.stderr != warning("NEW") || kc.Writes != 1 {
		t.Fatalf("code=%d writes=%d stderr=%q stdout=%q\nwant %q", r.code, kc.Writes, r.stderr, r.stdout, want)
	}
}

// TestTrustRevokeUnblocksAnInvalidTrustedSource: a trusted source that
// turned invalid blocks every write until it is fixed or revoked.
func TestTrustRevokeUnblocksAnInvalidTrustedSource(t *testing.T) {
	kc := fakeBundle(t, sv("ALPHA", "a"), sv("BAD", "b"))
	bad := opItem("item-bad", "Title BAD", onepass.Field{ID: "field-bad", Type: "CONCEALED", Label: "BAD"})
	op := fakeOp(varItem("ALPHA", "new"), bad)
	errRow := `{"var":"BAD","account":"my.1password.com","status":"error","detail":"item \"Title BAD\" (item-bad): BAD is empty"}` + "\n"

	r := runTrust(t, Deps{Keychain: kc, OnePass: op}, src("ALPHA").ID())
	if r.code != 1 || r.stdout != errRow+trailer(1) || kc.Writes != 0 {
		t.Fatalf("blocked: code=%d writes=%d stdout=%q", r.code, kc.Writes, r.stdout)
	}

	r = runTrust(t, Deps{Keychain: kc, OnePass: op}, "--revoke", src("BAD").ID())
	want := row("ALPHA", "changed") + revokedRow("BAD") + trailerOK
	if r.code != 0 || r.stdout != want || kc.Writes != 1 {
		t.Fatalf("revoke: code=%d writes=%d stdout=%q\nwant %q", r.code, kc.Writes, r.stdout, want)
	}
	wantTrusted(t, kc, src("ALPHA"))
}

// TestTrustSwapInPicker: unchecking one source of a name and checking
// another is a change to the var, with the revoke noted.
func TestTrustSwapInPicker(t *testing.T) {
	kc := fakeBundle(t, sv("TOKEN", "one"))
	planted := src2("item-token2", "TOKEN")
	r := runTrust(t, Deps{Keychain: kc, OnePass: twoAccountOp(), Picker: picking(planted)})
	want := `{"var":"TOKEN","account":"other.1password.com","status":"changed","detail":"` + multiDetail(src("TOKEN"), "revoked") + `"}` + "\n" + trailerOK
	if r.code != 0 || r.stdout != want || kc.Writes != 1 {
		t.Fatalf("code=%d writes=%d stdout=%q\nwant %q", r.code, kc.Writes, r.stdout, want)
	}
	wantTrusted(t, kc, planted)
}

func TestTrustRunsSyncGuards(t *testing.T) {
	t.Run("vanished account", func(t *testing.T) {
		kc := fakeBundle(t, sv("ALPHA", "a"))
		op := &onepass.Fake{AccountList: []onepass.Account{acct2}, Items: map[string][]onepass.Item{
			acct2.AccountUUID: {opItem("item-other", "Other", secret("OTHER", "o"))},
		}}
		r := runTrust(t, Deps{Keychain: kc, OnePass: op}, src2("item-other", "OTHER").ID())
		want := fatal("account_missing", "account ACCT user USER (my.1password.com) is in the keychain bundle but not in op account list", "envsec sync --forget-account ACCT")
		if r.code != 1 || r.stdout != "" || r.stderr != want || kc.Writes != 0 {
			t.Fatalf("code=%d writes=%d stdout=%q stderr=%q", r.code, kc.Writes, r.stdout, r.stderr)
		}
	})
	t.Run("zero items would drop another var", func(t *testing.T) {
		kc := fakeBundle(t, sv("ALPHA", "a"), sv("BETA", "b"))
		r := runTrust(t, Deps{Keychain: kc, OnePass: fakeOp()}, "--revoke", src("ALPHA").ID())
		if r.code != 1 || r.stdout != "" || !strings.Contains(r.stderr, `"error":"prune_refused"`) || kc.Writes != 0 {
			t.Fatalf("code=%d writes=%d stdout=%q stderr=%q", r.code, kc.Writes, r.stdout, r.stderr)
		}
	})
	t.Run("revoke leaves another vanished account", func(t *testing.T) {
		other := bundle.Var{Name: "OTHER", Value: marker + "-o", AccountUUID: "ACCT2", UserUUID: "USER2", AccountURL: "other.1password.com", VaultID: "vault", ItemID: "item-other", FieldID: "field-other"}
		kc := fakeBundle(t, sv("ALPHA", "a"), other)
		r := runTrust(t, Deps{Keychain: kc, OnePass: fakeOp(varItem("ALPHA", "a"))}, "--revoke", src("ALPHA").ID())
		want := fatal("account_missing", "account ACCT2 user USER2 (other.1password.com) is in the keychain bundle but not in op account list", "envsec sync --forget-account ACCT2")
		if r.code != 1 || r.stdout != "" || r.stderr != want || kc.Writes != 0 {
			t.Fatalf("code=%d writes=%d stdout=%q stderr=%q", r.code, kc.Writes, r.stdout, r.stderr)
		}
	})
}

// TestTrustRevokeReachesSourcesTheGuardsWouldProtect: an explicit revoke
// authorizes dropping that source and its var, so the guards judge only what
// is left.
func TestTrustRevokeReachesSourcesTheGuardsWouldProtect(t *testing.T) {
	gone := bundle.Source{AccountUUID: "ACCT9", UserUUID: "USER9", VaultID: "vault", ItemID: "item-gone", FieldID: "field-gone", Name: "GONE"}
	goneRow := func(s bundle.Source, account string) string {
		return fmt.Sprintf(`{"var":%q,"account":%q,"vault_id":"vault","item_id":%q,"field_id":%q,"source_id":%q,"status":"revoked","detail":"trust revoked"}`,
			s.Name, account, s.ItemID, s.FieldID, s.ID()) + "\n"
	}
	cases := map[string]struct {
		kc      *keychain.Fake
		op      *onepass.Fake
		revoke  bundle.Source
		want    string
		trusted []bundle.Source
	}{
		"only stored source, absent, zero items": {
			fakeTrusting(t, []bundle.Source{src("GONE")}), fakeOp(), src("GONE"),
			goneRow(src("GONE"), "") + trailerOK, nil},
		"only stored source, with a var, zero items": {
			fakeBundle(t, sv("ALPHA", "a")), fakeOp(), src("ALPHA"),
			goneRow(src("ALPHA"), "my.1password.com") + trailerOK, nil},
		"only record of a vanished account": {
			fakeTrusting(t, []bundle.Source{gone}, sv("ALPHA", "a")), fakeOp(varItem("ALPHA", "a")), gone,
			row("ALPHA", "unchanged") + goneRow(gone, "") + trailerOK, []bundle.Source{src("ALPHA")}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			r := runTrust(t, Deps{Keychain: tc.kc, OnePass: tc.op}, "--revoke", tc.revoke.ID())
			if r.stdout != tc.want {
				t.Fatalf("stdout = %q\nwant %q\nstderr %q", r.stdout, tc.want, r.stderr)
			}
			if r.code != 0 || r.stderr != "" || tc.kc.Writes != 1 {
				t.Fatalf("code=%d writes=%d stderr=%q", r.code, tc.kc.Writes, r.stderr)
			}
			if b := decodeFake(t, tc.kc); len(b.Vars) != len(tc.trusted) {
				t.Fatalf("bundle has %d vars", len(b.Vars))
			}
			wantTrusted(t, tc.kc, tc.trusted...)
		})
	}
}

// TestTrustPickerRevokesAPresentInvalidTrustedSource: the picker shows valid
// sources only. A trusted source whose value went empty is present, not
// absent, so a confirm revokes it instead of leaving every write blocked.
func TestTrustPickerRevokesAPresentInvalidTrustedSource(t *testing.T) {
	kc := fakeTrusting(t, []bundle.Source{src("GONE")}, sv("ALPHA", "a"), sv("BAD", "b"))
	bad := opItem("item-bad", "Title BAD", onepass.Field{ID: "field-bad", Type: "CONCEALED", Label: "BAD"})
	picker := picking(src("ALPHA"))
	r := runTrust(t, Deps{Keychain: kc, OnePass: fakeOp(varItem("ALPHA", "a"), bad), Picker: picker})
	want := row("ALPHA", "unchanged") + revokedRow("BAD") + trailerOK
	if r.stdout != want || r.code != 0 || r.stderr != "" || kc.Writes != 1 {
		t.Fatalf("code=%d writes=%d stderr=%q stdout=%q\nwant %q", r.code, kc.Writes, r.stderr, r.stdout, want)
	}
	if len(picker.Got) != 1 || picker.Got[0].Var != "ALPHA" || !picker.Got[0].Checked {
		t.Fatalf("options = %+v", picker.Got)
	}
	wantTrusted(t, kc, src("ALPHA"), src("GONE"))
}

// TestTrustPickerNothingChecked: a confirm with nothing checked revokes
// every source shown and keeps the absent ones. A cancel writes nothing.
func TestTrustPickerNothingChecked(t *testing.T) {
	op := func() *onepass.Fake { return fakeOp(varItem("ALPHA", "a"), varItem("BETA", "b")) }
	t.Run("confirm", func(t *testing.T) {
		kc := fakeTrusting(t, []bundle.Source{src("GONE")}, sv("ALPHA", "a"), sv("BETA", "b"))
		r := runTrust(t, Deps{Keychain: kc, OnePass: op(), Picker: &trustpicker.Fake{IsAvailable: true}})
		want := revokedRow("ALPHA") + revokedRow("BETA") + trailerOK
		if r.stdout != want || r.code != 0 || r.stderr != "" || kc.Writes != 1 {
			t.Fatalf("code=%d writes=%d stderr=%q stdout=%q\nwant %q", r.code, kc.Writes, r.stderr, r.stdout, want)
		}
		if b := decodeFake(t, kc); len(b.Vars) != 0 {
			t.Fatalf("bundle has %d vars", len(b.Vars))
		}
		wantTrusted(t, kc, src("GONE"))
	})
	t.Run("cancel", func(t *testing.T) {
		kc := fakeTrusting(t, []bundle.Source{src("GONE")}, sv("ALPHA", "a"), sv("BETA", "b"))
		before := string(kc.Value)
		r := runTrust(t, Deps{Keychain: kc, OnePass: op(), Picker: &trustpicker.Fake{IsAvailable: true, Err: trustpicker.ErrCancelled}})
		if r.code != 1 || r.stdout != "" || !strings.HasPrefix(r.stderr, `{"error":"trust_cancelled",`) || kc.Writes != 0 || string(kc.Value) != before {
			t.Fatalf("code=%d writes=%d stdout=%q stderr=%q", r.code, kc.Writes, r.stdout, r.stderr)
		}
	})
}

func TestTrustTakesTheSyncLock(t *testing.T) {
	useTempLock(t)
	release, err := acquireLock()
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	kc := fakeBundle(t, sv("ALPHA", "a"))
	op := fakeOp(varItem("ALPHA", "a"), varItem("BETA", "b"))
	// runCLI directly: runTrust would swap in a fresh lock path.
	r := runCLI(t, Deps{Keychain: kc, OnePass: op}, "trust", src("BETA").ID())
	if r.code != 1 || r.stdout != "" || !strings.HasPrefix(r.stderr, `{"error":"sync_locked",`) || kc.Writes != 0 || len(op.Calls) != 0 {
		t.Fatalf("code=%d writes=%d stdout=%q stderr=%q", r.code, kc.Writes, r.stdout, r.stderr)
	}
}

func TestTrustWriteFailurePrintsNoRows(t *testing.T) {
	kc := fakeBundle(t, sv("ALPHA", "a"))
	kc.WriteErr = &keychain.LockedError{KeychainPath: "/k/login.keychain-db"}
	r := runTrust(t, Deps{Keychain: kc, OnePass: fakeOp(varItem("ALPHA", "a"), varItem("BETA", "b"))}, src("BETA").ID())
	if r.code != 4 || r.stdout != "" || !strings.HasPrefix(r.stderr, `{"error":"keychain_locked",`) {
		t.Fatalf("code=%d stdout=%q stderr=%q", r.code, r.stdout, r.stderr)
	}
}

// TestTrustRevokeTwoSourcesOfOneNameIsOneRow: one present, one absent, both
// named TOKEN. One row per var name still holds.
func TestTrustRevokeTwoSourcesOfOneNameIsOneRow(t *testing.T) {
	absent := src("TOKEN")
	absent.ItemID = "item-token-old"
	kc := fakeTrusting(t, []bundle.Source{absent}, sv("TOKEN", "one"), sv("ALPHA", "a"))
	r := runTrust(t, Deps{Keychain: kc, OnePass: fakeOp(varItem("TOKEN", "one"), varItem("ALPHA", "a"))}, "--revoke", src("TOKEN").ID(), absent.ID())
	want := row("ALPHA", "unchanged") +
		`{"var":"TOKEN","account":"","status":"revoked","detail":"` + multiDetail(src("TOKEN"), "revoked") + "; " + multiDetail(absent, "revoked") + `"}` + "\n" + trailerOK
	if r.code != 0 || r.stdout != want || kc.Writes != 1 {
		t.Fatalf("code=%d writes=%d stdout=%q\nwant %q", r.code, kc.Writes, r.stdout, want)
	}
	wantTrusted(t, kc, src("ALPHA"))
}

// TestNoCommandButEnvPrintsAValue runs one resolution, with a trusted, an
// untrusted, and an invalid source, through every command that reads
// 1Password. The run helpers fail on any output holding a value.
func TestNoCommandButEnvPrintsAValue(t *testing.T) {
	op := func() *onepass.Fake {
		return fakeOp(varItem("ALPHA", "new"), varItem("BETA", "b"), varItem("NL", "a\nb"))
	}
	kc := fakeBundle(t, sv("ALPHA", "old"))
	if !strings.Contains(decodeFake(t, kc).Vars[0].Value, marker) {
		t.Fatal("fixture values do not carry the marker")
	}
	runCheck(t, kc, op())
	runSync(t, Deps{Keychain: kc, OnePass: op()})
	runTrust(t, Deps{Keychain: kc, OnePass: op()}, src("BETA").ID())
	runTrust(t, Deps{Keychain: kc, OnePass: op(), Picker: picking(src("ALPHA"))})
	runTrust(t, Deps{Keychain: kc, OnePass: op()}, "--revoke", src("ALPHA").ID())
	noValues(t, runCLI(t, Deps{Keychain: kc}, "list"))
	if kc.Writes != 4 {
		t.Fatalf("writes = %d, want every sync and trust to have written", kc.Writes)
	}
}
