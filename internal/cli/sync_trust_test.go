package cli

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/tammersaleh/envsec/internal/bundle"
	"github.com/tammersaleh/envsec/internal/keychain"
	"github.com/tammersaleh/envsec/internal/onepass"
	"github.com/tammersaleh/envsec/internal/trustpicker"
)

const warnPrefix = "envsec: untrusted sources for "

func warning(names ...string) string {
	return warnPrefix + strings.Join(names, ", ") + "; run envsec trust\n"
}

// multiDetail is the detail one source contributes to a row that stands for
// more than that source.
func multiDetail(s bundle.Source, what string) string {
	return fmt.Sprintf("source %s %s (item %s field %s)", s.ID(), what, s.ItemID, s.FieldID)
}

func TestSyncFirstRunPickSubset(t *testing.T) {
	kc := &keychain.Fake{}
	picker := picking(src("ALPHA"))
	r := runSync(t, Deps{Keychain: kc, OnePass: fakeOp(varItem("ZED", "z"), varItem("ALPHA", "a")), Picker: picker})
	want := row("ALPHA", "added") + untrustedRow("ZED") + trailer(1)
	if r.stdout != want {
		t.Fatalf("stdout = %q\nwant %q", r.stdout, want)
	}
	if r.code != 1 || r.stderr != warning("ZED") || kc.Writes != 1 {
		t.Fatalf("code=%d writes=%d stderr=%q", r.code, kc.Writes, r.stderr)
	}
	b := decodeFake(t, kc)
	if len(b.Vars) != 1 || b.Vars[0] != sv("ALPHA", "a") {
		t.Fatalf("bundle has %d vars or the wrong one", len(b.Vars))
	}
	wantTrusted(t, kc, src("ALPHA"))

	// The picker saw every valid source, nothing checked, with the strings
	// it shows.
	wantOpts := []trustpicker.Option{
		{ID: src("ALPHA").ID(), Var: "ALPHA", Account: "my.1password.com", Vault: "Private", Item: "Title ALPHA"},
		{ID: src("ZED").ID(), Var: "ZED", Account: "my.1password.com", Vault: "Private", Item: "Title ZED"},
	}
	if picker.Calls != 1 || len(picker.Got) != 2 || picker.Got[0] != wantOpts[0] || picker.Got[1] != wantOpts[1] {
		t.Fatalf("picker calls=%d options=%+v", picker.Calls, picker.Got)
	}
}

func TestSyncFirstRunPickerLeavesOutInvalidSources(t *testing.T) {
	kc := &keychain.Fake{}
	picker := picking(src("ALPHA"))
	r := runSync(t, Deps{Keychain: kc, OnePass: fakeOp(varItem("ALPHA", "a"), varItem("PATH", "p")), Picker: picker})
	if len(picker.Got) != 1 || picker.Got[0].Var != "ALPHA" {
		t.Fatalf("options = %+v", picker.Got)
	}
	want := row("ALPHA", "added") +
		`{"var":"PATH","account":"my.1password.com","status":"error","detail":"item \"Title PATH\" (item-path): label PATH is denylisted"}` + "\n" + trailer(1)
	if r.stdout != want || r.code != 1 || r.stderr != "" || kc.Writes != 1 {
		t.Fatalf("code=%d writes=%d stderr=%q stdout=%q\nwant %q", r.code, kc.Writes, r.stderr, r.stdout, want)
	}
}

func TestSyncFirstRunWritesNothingWithoutASelection(t *testing.T) {
	op := func() *onepass.Fake { return fakeOp(varItem("ZED", "z"), varItem("ALPHA", "a"), varItem("PATH", "p")) }
	rows := untrustedRow("ALPHA") +
		`{"var":"PATH","account":"my.1password.com","status":"error","detail":"item \"Title PATH\" (item-path): label PATH is denylisted"}` + "\n" +
		untrustedRow("ZED") + trailer(3)
	cases := map[string]struct {
		picker    *trustpicker.Fake
		wantCalls int
	}{
		"confirm with nothing checked": {&trustpicker.Fake{IsAvailable: true}, 1},
		"no terminal":                  {&trustpicker.Fake{Selection: []string{src("ALPHA").ID()}}, 0},
	}
	for name, tc := range cases {
		for kcName, kc := range map[string]*keychain.Fake{
			"no bundle":     {},
			"empty bundle":  fakeBundle(t),
			"legacy bundle": legacyBundle(t, sv("ALPHA", "a")),
		} {
			t.Run(name+"/"+kcName, func(t *testing.T) {
				tc.picker.Calls = 0
				before := string(kc.Value)
				r := runSync(t, Deps{Keychain: kc, OnePass: op(), Picker: tc.picker})
				if r.stdout != rows {
					t.Fatalf("stdout = %q\nwant %q", r.stdout, rows)
				}
				if r.code != 1 || r.stderr != warning("ALPHA", "ZED") || kc.Writes != 0 || string(kc.Value) != before {
					t.Fatalf("code=%d writes=%d stderr=%q", r.code, kc.Writes, r.stderr)
				}
				if tc.picker.Calls != tc.wantCalls {
					t.Fatalf("picker calls = %d, want %d", tc.picker.Calls, tc.wantCalls)
				}
			})
		}
	}
}

func TestSyncFirstRunPickerCancelled(t *testing.T) {
	for name, perr := range map[string]error{
		"cancel":         trustpicker.ErrCancelled,
		"wrapped cancel": fmt.Errorf("ctrl-c: %w", trustpicker.ErrCancelled),
		"terminal error": errors.New("tty went away " + marker),
	} {
		t.Run(name, func(t *testing.T) {
			kc := &keychain.Fake{}
			picker := &trustpicker.Fake{IsAvailable: true, Err: perr, Selection: []string{src("ALPHA").ID()}}
			r := runSync(t, Deps{Keychain: kc, OnePass: fakeOp(varItem("ALPHA", "a")), Picker: picker})
			if r.code != 1 || r.stdout != "" || kc.Writes != 0 {
				t.Fatalf("code=%d writes=%d stdout=%q", r.code, kc.Writes, r.stdout)
			}
			if !strings.HasPrefix(r.stderr, `{"error":"trust_cancelled",`) || strings.Count(r.stderr, "\n") != 1 || !strings.Contains(r.stderr, `"hint":"envsec trust"`) {
				t.Fatalf("stderr = %q", r.stderr)
			}
		})
	}
}

func TestSyncPickerReturningAnUnknownIDWritesNothing(t *testing.T) {
	kc := &keychain.Fake{}
	picker := &trustpicker.Fake{IsAvailable: true, Selection: []string{src("ALPHA").ID(), src("NOPE").ID()}}
	r := runSync(t, Deps{Keychain: kc, OnePass: fakeOp(varItem("ALPHA", "a")), Picker: picker})
	if r.code != 1 || r.stdout != "" || kc.Writes != 0 || !strings.HasPrefix(r.stderr, `{"error":"trust_cancelled",`) {
		t.Fatalf("code=%d writes=%d stdout=%q stderr=%q", r.code, kc.Writes, r.stdout, r.stderr)
	}
}

func TestSyncLegacyBundleIsNothingTrusted(t *testing.T) {
	kc := legacyBundle(t, sv("ALPHA", "a"), sv("OLD", "o"))
	picker := picking(src("ALPHA"))
	r := runSync(t, Deps{Keychain: kc, OnePass: fakeOp(varItem("ALPHA", "a"), varItem("ZED", "z")), Picker: picker})
	// ALPHA is diffed against the schema 1 copy. A missing vault id alone
	// is not a change.
	want := row("ALPHA", "unchanged") + row("OLD", "removed") + untrustedRow("ZED") + trailer(1)
	if r.stdout != want || r.code != 1 || kc.Writes != 1 || picker.Calls != 1 {
		t.Fatalf("code=%d writes=%d picker=%d stdout=%q\nwant %q", r.code, kc.Writes, picker.Calls, r.stdout, want)
	}
	b := decodeFake(t, kc)
	if b.Schema != bundle.Schema || len(b.Vars) != 1 || b.Vars[0] != sv("ALPHA", "a") {
		t.Fatalf("bundle schema=%d vars=%d", b.Schema, len(b.Vars))
	}
	wantTrusted(t, kc, src("ALPHA"))
}

func TestSyncLaterRunWithNewUntrustedSource(t *testing.T) {
	kc := fakeBundle(t, sv("ALPHA", "old"))
	picker := picking(src("NEW"))
	r := runSync(t, Deps{Keychain: kc, OnePass: fakeOp(varItem("ALPHA", "new"), varItem("NEW", "n")), Picker: picker})
	want := row("ALPHA", "changed") + untrustedRow("NEW") + trailer(1)
	if r.stdout != want {
		t.Fatalf("stdout = %q\nwant %q", r.stdout, want)
	}
	if r.code != 1 || r.stderr != warning("NEW") || kc.Writes != 1 {
		t.Fatalf("code=%d writes=%d stderr=%q", r.code, kc.Writes, r.stderr)
	}
	// Trust exists, so the picker never opens, terminal or not.
	if picker.Calls != 0 {
		t.Fatalf("picker calls = %d", picker.Calls)
	}
	b := decodeFake(t, kc)
	if len(b.Vars) != 1 || b.Vars[0] != sv("ALPHA", "new") {
		t.Fatalf("bundle has %d vars or ALPHA was not updated", len(b.Vars))
	}
	wantTrusted(t, kc, src("ALPHA"))
}

// TestSyncPlantedSourceWithATrustedName: another account defines TOKEN too.
// It is not a conflict. The trusted value is written and the name is
// reported untrusted, once.
func TestSyncPlantedSourceWithATrustedName(t *testing.T) {
	kc := fakeBundle(t, sv("TOKEN", "old"))
	r := runSync(t, Deps{Keychain: kc, OnePass: twoAccountOp()})
	planted := src2("item-token2", "TOKEN")
	want := `{"var":"TOKEN","account":"other.1password.com","vault":"Private","vault_id":"vault","item":"Other token","item_id":"item-token2","field_id":"field-token","source_id":"` + planted.ID() + `","status":"untrusted","detail":"source is not trusted"}` + "\n" + trailer(1)
	if r.stdout != want {
		t.Fatalf("stdout = %q\nwant %q", r.stdout, want)
	}
	if r.code != 1 || r.stderr != warning("TOKEN") || kc.Writes != 1 {
		t.Fatalf("code=%d writes=%d stderr=%q", r.code, kc.Writes, r.stderr)
	}
	b := decodeFake(t, kc)
	if len(b.Vars) != 1 || b.Vars[0] != sv("TOKEN", "one") {
		t.Fatalf("bundle has %d vars or TOKEN is not the trusted source's value", len(b.Vars))
	}
	wantTrusted(t, kc, src("TOKEN"))
}

func TestSyncSeveralUntrustedSourcesForOneNameIsOneRow(t *testing.T) {
	kc := fakeBundle(t, sv("ALPHA", "a"))
	op := twoAccountOp()
	op.Items[acct1.AccountUUID] = append(op.Items[acct1.AccountUUID], varItem("ALPHA", "a"))
	r := runSync(t, Deps{Keychain: kc, OnePass: op})
	detail := multiDetail(src("TOKEN"), "is not trusted") + "; " + multiDetail(src2("item-token2", "TOKEN"), "is not trusted")
	want := row("ALPHA", "unchanged") +
		`{"var":"TOKEN","account":"","status":"untrusted","detail":"` + detail + `"}` + "\n" + trailer(1)
	if r.stdout != want {
		t.Fatalf("stdout = %q\nwant %q", r.stdout, want)
	}
	if r.code != 1 || r.stderr != warning("TOKEN") || kc.Writes != 1 {
		t.Fatalf("code=%d writes=%d stderr=%q", r.code, kc.Writes, r.stderr)
	}
}

func TestSyncUntrustedAndInvalidSourcesForOneNameIsOneErrorRow(t *testing.T) {
	kc := fakeBundle(t, sv("ALPHA", "a"))
	empty := opItem("item-empty", "Empty", onepass.Field{ID: "field-token-e", Type: "CONCEALED", Label: "TOKEN"})
	r := runSync(t, Deps{Keychain: kc, OnePass: fakeOp(varItem("ALPHA", "a"), varItem("TOKEN", "t"), empty)})
	want := row("ALPHA", "unchanged") +
		`{"var":"TOKEN","account":"my.1password.com","status":"error","detail":"item \"Empty\" (item-empty): TOKEN is empty; ` + multiDetail(src("TOKEN"), "is not trusted") + `"}` + "\n" + trailer(1)
	if r.stdout != want {
		t.Fatalf("stdout = %q\nwant %q", r.stdout, want)
	}
	if r.code != 1 || r.stderr != warning("TOKEN") || kc.Writes != 1 {
		t.Fatalf("code=%d writes=%d stderr=%q", r.code, kc.Writes, r.stderr)
	}
}

func TestSyncWriteFailurePrintsNoRowsAndNoWarning(t *testing.T) {
	kc := fakeBundle(t, sv("ALPHA", "old"))
	kc.WriteErr = &keychain.UnavailableError{Detail: "locked"}
	r := runSync(t, Deps{Keychain: kc, OnePass: fakeOp(varItem("ALPHA", "new"), varItem("NEW", "n"))})
	want := `{"error":"keychain_unavailable","detail":"keychain unavailable: locked","hint":"unlock the login keychain and rerun envsec sync"}` + "\n"
	if r.code != 4 || r.stdout != "" || r.stderr != want {
		t.Fatalf("code=%d stdout=%q stderr=%q", r.code, r.stdout, r.stderr)
	}
}

// TestSyncTrustedSourceAbsentThenBack: a trusted source that leaves
// 1Password loses its var and keeps its trust, so it comes back with no new
// trust step.
func TestSyncTrustedSourceAbsentThenBack(t *testing.T) {
	kc := fakeBundle(t, sv("ALPHA", "a"), sv("ZED", "z"))
	picker := &trustpicker.Fake{IsAvailable: true}
	r := runSync(t, Deps{Keychain: kc, OnePass: fakeOp(varItem("ALPHA", "a")), Picker: picker})
	if r.code != 0 || r.stdout != row("ALPHA", "unchanged")+row("ZED", "removed")+trailerOK {
		t.Fatalf("code=%d stdout=%q stderr=%q", r.code, r.stdout, r.stderr)
	}
	if b := decodeFake(t, kc); len(b.Vars) != 1 {
		t.Fatalf("bundle has %d vars", len(b.Vars))
	}
	wantTrusted(t, kc, src("ALPHA"), src("ZED"))

	r = runSync(t, Deps{Keychain: kc, OnePass: fakeOp(varItem("ALPHA", "a"), varItem("ZED", "z2")), Picker: picker})
	if r.code != 0 || r.stderr != "" || r.stdout != row("ALPHA", "unchanged")+row("ZED", "added")+trailerOK {
		t.Fatalf("code=%d stdout=%q stderr=%q", r.code, r.stdout, r.stderr)
	}
	if b := decodeFake(t, kc); len(b.Vars) != 2 || b.Vars[1] != sv("ZED", "z2") {
		t.Fatalf("bundle has %d vars or ZED is wrong", len(b.Vars))
	}
	if picker.Calls != 0 {
		t.Fatalf("picker calls = %d", picker.Calls)
	}
}

// TestSyncAllTrustAbsentDoesNotReopenThePicker: the picker is for an empty
// trusted list, not for one whose sources are all gone.
func TestSyncAllTrustAbsentDoesNotReopenThePicker(t *testing.T) {
	kc := fakeBundle(t, sv("ZED", "z"))
	picker := picking(src("ALPHA"))
	r := runSync(t, Deps{Keychain: kc, OnePass: fakeOp(varItem("ALPHA", "a")), Picker: picker})
	if r.code != 1 || r.stdout != untrustedRow("ALPHA")+row("ZED", "removed")+trailer(1) || picker.Calls != 0 || kc.Writes != 1 {
		t.Fatalf("code=%d writes=%d picker=%d stdout=%q", r.code, kc.Writes, picker.Calls, r.stdout)
	}
	wantTrusted(t, kc, src("ZED"))
}

// TestSyncProvenanceChangeNeedsTrustAgain: any part of the tuple changing,
// the label included, is a new source.
func TestSyncProvenanceChangeNeedsTrustAgain(t *testing.T) {
	kc := fakeBundle(t, sv("ALPHA", "a"))
	moved := varItem("ALPHA", "a")
	moved.Vault = onepass.Vault{ID: "vault-shared", Name: "Shared"}
	r := runSync(t, Deps{Keychain: kc, OnePass: fakeOp(moved)})
	movedSrc := src("ALPHA")
	movedSrc.VaultID = "vault-shared"
	want := `{"var":"ALPHA","account":"my.1password.com","vault":"Shared","vault_id":"vault-shared","item":"Title ALPHA","item_id":"item-alpha","field_id":"field-alpha","source_id":"` + movedSrc.ID() + `","status":"untrusted","detail":"source is not trusted"}` + "\n" + trailer(1)
	if r.stdout != want || r.code != 1 || kc.Writes != 1 {
		t.Fatalf("code=%d writes=%d stdout=%q\nwant %q", r.code, kc.Writes, r.stdout, want)
	}
	if b := decodeFake(t, kc); len(b.Vars) != 0 {
		t.Fatalf("bundle has %d vars, want the moved var gone", len(b.Vars))
	}
	wantTrusted(t, kc, src("ALPHA"))
}

// TestSyncHostileStringsStayInsideJSON: vault names and item titles come
// from 1Password, where anyone with write access to a shared vault picks
// them. They reach stdout through the JSON encoder only and never reach the
// warning line.
func TestSyncHostileStringsStayInsideJSON(t *testing.T) {
	kc := fakeBundle(t, sv("ALPHA", "a"))
	evil := varItem("EVIL", "e")
	evil.Title = "x\x1b[2J\n{\"var\":\"FAKE\"}"
	evil.Vault.Name = "v\r\x07"
	r := runSync(t, Deps{Keychain: kc, OnePass: fakeOp(varItem("ALPHA", "a"), evil)})
	if r.code != 1 || strings.Count(r.stdout, "\n") != 3 {
		t.Fatalf("code=%d stdout=%q", r.code, r.stdout)
	}
	for _, raw := range []string{"\x1b", "\r", "\x07"} {
		if strings.Contains(r.stdout, raw) || strings.Contains(r.stderr, raw) {
			t.Fatalf("raw control byte %q in output\nstdout=%q\nstderr=%q", raw, r.stdout, r.stderr)
		}
	}
	if r.stderr != warning("EVIL") {
		t.Fatalf("stderr = %q", r.stderr)
	}
}

// TestSyncForgetAccountIsWrittenEvenWithNothingTrusted: forgetting the last
// trusted account is a change of its own. It is written whether or not the
// user then trusts anything, or a rerun would ask for the flag forever.
func TestSyncForgetAccountIsWrittenEvenWithNothingTrusted(t *testing.T) {
	other := src2("item-other", "OTHER")
	otherRow := `{"var":"OTHER","account":"other.1password.com","vault":"Private","vault_id":"vault","item":"Other","item_id":"item-other","field_id":"field-other","source_id":"` + other.ID() + `","status":"untrusted","detail":"source is not trusted"}` + "\n"
	for name, tc := range map[string]struct {
		picker    *trustpicker.Fake
		wantCalls int
	}{
		"no terminal":                  {&trustpicker.Fake{}, 0},
		"confirm with nothing checked": {&trustpicker.Fake{IsAvailable: true}, 1},
	} {
		for kcName, kc := range map[string]*keychain.Fake{
			"trusted var": fakeTrusting(t, []bundle.Source{src("GONE")}, sv("ALPHA", "a")),
			"legacy var":  legacyBundle(t, sv("ALPHA", "a")),
		} {
			t.Run(name+"/"+kcName, func(t *testing.T) {
				op := &onepass.Fake{AccountList: []onepass.Account{acct2}, Items: map[string][]onepass.Item{
					acct2.AccountUUID: {opItem("item-other", "Other", secret("OTHER", "o"))},
				}}
				tc.picker.Calls = 0
				r := runSync(t, Deps{Keychain: kc, OnePass: op, Picker: tc.picker}, "--forget-account", "ACCT")
				want := row("ALPHA", "removed") + otherRow + trailer(1)
				if r.stdout != want {
					t.Fatalf("stdout = %q\nwant %q\nstderr %q", r.stdout, want, r.stderr)
				}
				if r.code != 1 || r.stderr != warning("OTHER") || kc.Writes != 1 || tc.picker.Calls != tc.wantCalls {
					t.Fatalf("code=%d writes=%d picker=%d stderr=%q", r.code, kc.Writes, tc.picker.Calls, r.stderr)
				}
				b := decodeFake(t, kc)
				if len(b.Vars) != 0 || len(b.TrustedSources) != 0 {
					t.Fatalf("bundle keeps %d vars and %d trusted sources", len(b.Vars), len(b.TrustedSources))
				}
				// The rerun no longer needs the flag.
				r = runSync(t, Deps{Keychain: kc, OnePass: op})
				if r.code != 1 || r.stdout != otherRow+trailer(1) || kc.Writes != 1 {
					t.Fatalf("rerun: code=%d writes=%d stdout=%q stderr=%q", r.code, kc.Writes, r.stdout, r.stderr)
				}
			})
		}
	}
}
