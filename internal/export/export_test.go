package export

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tammersaleh/envsec/internal/bundle"
)

func TestLabelPattern(t *testing.T) {
	tests := map[string]bool{
		"A":               true,
		"GRAFANA_TOKEN":   true,
		"X1_2":            true,
		"":                false,
		"a":               false,
		"_A":              false,
		"1A":              false,
		"grafana_token":   false,
		"GRAFANA-TOKEN":   false,
		"GRAFANA TOKEN":   false,
		"GRAFANA_TOKEN\n": false,
		"username":        false,
		"Ünicode":         false,
	}
	for in, want := range tests {
		if got := LabelPattern.MatchString(in); got != want {
			t.Errorf("LabelPattern(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestDenied(t *testing.T) {
	tests := map[string]bool{
		"PATH":                     true,
		"HOME":                     true,
		"USER":                     true,
		"LOGNAME":                  true,
		"SHELL":                    true,
		"TMPDIR":                   true,
		"UID":                      true,
		"EUID":                     true,
		"IFS":                      true,
		"FPATH":                    true,
		"ZDOTDIR":                  true,
		"ENV":                      true,
		"SHLVL":                    true,
		"TERM":                     true,
		"LANG":                     true,
		"NODE_OPTIONS":             true,
		"GIT_SSH_COMMAND":          true,
		"PROMPT":                   true,
		"PS1":                      true,
		"PS2":                      true,
		"PS3":                      true,
		"PS4":                      true,
		"RPROMPT":                  true,
		"RPS1":                     true,
		"RPS2":                     true,
		"PROMPT2":                  true,
		"PROMPT3":                  true,
		"PROMPT4":                  true,
		"SPROMPT":                  true,
		"PPID":                     true,
		"LINENO":                   true,
		"RANDOM":                   true,
		"SECONDS":                  true,
		"COLUMNS":                  true,
		"LINES":                    true,
		"HISTSIZE":                 true,
		"SAVEHIST":                 true,
		"HISTFILE":                 true,
		"GID":                      true,
		"EGID":                     true,
		"USERNAME":                 true,
		"RPROMPT2":                 true,
		"KEYTIMEOUT":               true,
		"FUNCNEST":                 true,
		"LISTMAX":                  true,
		"MAILCHECK":                true,
		"OPTIND":                   true,
		"TRY_BLOCK_ERROR":          true,
		"TRY_BLOCK_INTERRUPT":      true,
		"ARGC":                     true,
		"HISTCMD":                  true,
		"TTYIDLE":                  true,
		"ZSH_VERSION":              true,
		"ZSH_":                     true,
		"OP_SERVICE_ACCOUNT_TOKEN": true,
		"OP_":                      true,
		"LC_ALL":                   true,
		"LC_":                      true,
		"DYLD_INSERT_LIBRARIES":    true,
		"LD_PRELOAD":               true,
		"ENVSEC_MANAGED_VARS":      true,
		"ENVSEC_X":                 true,
		"BASH_ENV":                 true,
		"MAILPATH":                 true,
		"PROMPT_EOL_MARK":          true,
		"GIT_CONFIG_COUNT":         true,
		"GIT_CONFIG_KEY_0":         true,
		"GIT_CONFIG_VALUE_0":       true,
		"GIT_CONFIG_PARAMETERS":    true,
		"GIT_CONFIG_":              true,
		"GIT_CONFIG":               false,
		"GIT_CONFIGURATION":        false,
		"MY_GIT_CONFIG_COUNT":      false,
		"GITHUB_TOKEN":             false,
		"MAILGUN_API_KEY":          false,
		"MAILPATHS":                false,
		"BASH_ENVIRONMENT_TOKEN":   false,
		"MY_BASH_ENV":              false,
		"PROMPT_EOL":               false,
		"PROMPT_EOL_MARKER":        false,
		"PATHS":                    false,
		"MYPATH":                   false,
		"GRAFANA_TOKEN":            false,
		"ENVIRONMENT":              false,
		"TERMINAL":                 false,
		"LANGUAGE":                 false,
		"LCX":                      false,
		"ENVSEC":                   false,
		"OPTIONS":                  false,
		"PROMPTS":                  false,
		"GIDS":                     false,
		"ZSH":                      false,
		"ZSHRC":                    false,
		"MYZSH_X":                  false,
		"path":                     false,
	}
	for in, want := range tests {
		if got := Denied(in); got != want {
			t.Errorf("Denied(%q) = %v, want %v", in, got, want)
		}
	}
}

func item(fields ...Field) Item {
	return Item{
		ID:          "item-1",
		Title:       "Grafana",
		VaultID:     "vault-1",
		VaultName:   "Private",
		AccountUUID: "acct-1",
		UserUUID:    "user-1",
		AccountURL:  "my.1password.com",
		Tags:        []string{"shell-env"},
		Fields:      fields,
	}
}

func concealed(id, label, value string) Field {
	return Field{ID: id, Type: "CONCEALED", Label: label, Value: value}
}

func TestSelect(t *testing.T) {
	tests := []struct {
		name     string
		item     Item
		wantVars []string // names, in field order
		wantErrs []string // substrings, one per expected error
	}{
		{
			name: "mixed types, only concealed matching labels",
			item: item(
				Field{ID: "f0", Type: "STRING", Label: "username", Value: "bob"},
				concealed("f1", "GRAFANA_TOKEN", "tok"),
				Field{ID: "f2", Type: "STRING", Label: "NOT_CONCEALED", Value: "x"},
				Field{ID: "f3", Type: "URL", Label: "website", Value: "https://x"},
				Field{ID: "f4", Type: "CONCEALED", Label: "", Value: "unlabeled"},
			),
			wantVars: []string{"GRAFANA_TOKEN"},
		},
		{
			name: "non-matching concealed label ignored",
			item: item(
				concealed("f1", "password", "secret"),
				concealed("f2", "api key", "secret"),
			),
		},
		{
			name: "multi-var item",
			item: item(
				concealed("f1", "B_TOKEN", "b"),
				concealed("f2", "A_TOKEN", "a"),
			),
			wantVars: []string{"B_TOKEN", "A_TOKEN"},
		},
		{
			name:     "exact denylist hit",
			item:     item(concealed("f1", "PATH", "x"), concealed("f2", "OK_VAR", "y")),
			wantVars: []string{"OK_VAR"},
			wantErrs: []string{"PATH"},
		},
		{
			name:     "prefix denylist hit",
			item:     item(concealed("f1", "ENVSEC_MANAGED_VARS", "x")),
			wantErrs: []string{"ENVSEC_MANAGED_VARS"},
		},
		{
			name: "names that make a program run their value",
			item: item(
				concealed("f1", "BASH_ENV", "x"),
				concealed("f2", "MAILPATH", "x"),
				concealed("f3", "PROMPT_EOL_MARK", "x"),
				concealed("f4", "GIT_CONFIG_COUNT", "1"),
				concealed("f5", "GIT_CONFIG_KEY_0", "x"),
				concealed("f6", "GIT_CONFIG_VALUE_0", "x"),
				concealed("f7", "GIT_CONFIG_PARAMETERS", "x"),
				concealed("f8", "GIT_CONFIG", "x"),
				concealed("f9", "GITHUB_TOKEN", "x"),
			),
			wantVars: []string{"GIT_CONFIG", "GITHUB_TOKEN"},
			wantErrs: []string{
				"BASH_ENV", "MAILPATH", "PROMPT_EOL_MARK", "GIT_CONFIG_COUNT",
				"GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0", "GIT_CONFIG_PARAMETERS",
			},
		},
		{
			name:     "duplicate label in item is not a selection error",
			item:     item(concealed("f1", "TOKEN", "a"), concealed("f2", "TOKEN", "b")),
			wantVars: []string{"TOKEN", "TOKEN"},
		},
		{
			name:     "empty value",
			item:     item(concealed("f1", "TOKEN", "")),
			wantErrs: []string{"TOKEN"},
		},
		{
			name:     "value with LF",
			item:     item(concealed("f1", "TOKEN", "a\nb")),
			wantErrs: []string{"TOKEN"},
		},
		{
			name:     "value with CR",
			item:     item(concealed("f1", "TOKEN", "a\rb")),
			wantErrs: []string{"TOKEN"},
		},
		{
			name:     "value with tab",
			item:     item(concealed("f1", "TOKEN", "a\tb")),
			wantErrs: []string{"TOKEN"},
		},
		{
			name:     "value with ESC",
			item:     item(concealed("f1", "TOKEN", "a\x1bb")),
			wantErrs: []string{"TOKEN"},
		},
		{
			name:     "value with DEL",
			item:     item(concealed("f1", "TOKEN", "a\x7fb")),
			wantErrs: []string{"TOKEN"},
		},
		{
			name:     "value with NUL",
			item:     item(concealed("f1", "TOKEN", "a\x00b")),
			wantErrs: []string{"TOKEN"},
		},
		{
			name:     "value that is not valid UTF-8",
			item:     item(concealed("f1", "TOKEN", "a\xffb")),
			wantErrs: []string{"TOKEN"},
		},
		{
			name: "printable values pass",
			item: item(
				concealed("f1", "PLAIN", "abc123"),
				concealed("f2", "SPACES", "two words here"),
				concealed("f3", "QUOTE", "it's"),
				concealed("f4", "MULTIBYTE", "日本語 ñ é"),
				concealed("f5", "SHELL_META", "$x `y` \\ !"),
			),
			wantVars: []string{"PLAIN", "SPACES", "QUOTE", "MULTIBYTE", "SHELL_META"},
		},
		{
			name: "all errors returned, not just the first",
			item: item(
				concealed("f1", "HOME", "x"),
				concealed("f2", "EMPTY", ""),
				concealed("f3", "GOOD", "ok"),
				concealed("f4", "LD_PRELOAD", "x"),
			),
			wantVars: []string{"GOOD"},
			wantErrs: []string{"HOME", "EMPTY", "LD_PRELOAD"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			vars, errs := Select(tc.item)
			var names []string
			for _, v := range vars {
				names = append(names, v.Source.Name)
			}
			if !reflect.DeepEqual(names, tc.wantVars) {
				t.Errorf("vars = %v, want %v", names, tc.wantVars)
			}
			if len(errs) != len(tc.wantErrs) {
				t.Fatalf("errors = %v, want %d matching %v", errs, len(tc.wantErrs), tc.wantErrs)
			}
			for i, want := range tc.wantErrs {
				msg := errs[i].Error()
				if !strings.Contains(msg, want) {
					t.Errorf("error %d = %q, want mention of %q", i, msg, want)
				}
				if !strings.Contains(msg, tc.item.Title) || !strings.Contains(msg, tc.item.ID) {
					t.Errorf("error %d = %q, want item title and ID", i, msg)
				}
				if errs[i].Source.Name != want || errs[i].Source.ItemID != tc.item.ID || errs[i].ItemTitle != tc.item.Title || errs[i].Reason == "" {
					t.Errorf("error %d fields = %+v, want label %q", i, errs[i], want)
				}
			}
		})
	}
}

func TestSelectErrorsNeverContainValues(t *testing.T) {
	const secret = "s3cr3t-value-xyz"
	_, errs := Select(item(
		concealed("f1", "PATH", secret),
		concealed("f2", "TOKEN", secret+"\n"),
		concealed("f3", "TOKEN", secret),
	))
	if len(errs) == 0 {
		t.Fatal("expected errors")
	}
	for _, err := range errs {
		if strings.Contains(err.Error(), secret) {
			t.Errorf("error leaks value: %q", err.Error())
		}
	}
}

func TestSelectControlByteErrorsNeverContainValues(t *testing.T) {
	const secret = "s3cr3t-value-xyz"
	for name, suffix := range map[string]string{
		"tab": "\t", "ESC": "\x1b", "DEL": "\x7f", "NUL": "\x00", "CR": "\r", "LF": "\n", "invalid utf8": "\xff",
	} {
		t.Run(name, func(t *testing.T) {
			_, errs := Select(item(concealed("f1", "TOKEN", secret+suffix+secret)))
			if len(errs) != 1 {
				t.Fatalf("errs = %v, want one", errs)
			}
			if msg := errs[0].Error(); strings.Contains(msg, secret) || strings.Contains(msg, suffix) {
				t.Errorf("error leaks value: %q", msg)
			}
		})
	}
}

func TestCheckValue(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string // exact error text; empty means valid
	}{
		{"plain ASCII", "abc123", ""},
		{"spaces", "two words here", ""},
		{"single quote", "it's", ""},
		{"multi-byte UTF-8", "日本語 ñ é", ""},
		{"shell metacharacters", "$x `y` \\ !", ""},
		{"first printable byte", " ", ""},
		{"last printable ASCII byte", "~", ""},
		{"empty is allowed here", "", ""},
		{"tab", "a\tb", "contains control byte 0x09"},
		{"ESC", "a\x1bb", "contains control byte 0x1b"},
		{"DEL", "a\x7fb", "contains control byte 0x7f"},
		{"NUL", "a\x00b", "contains control byte 0x00"},
		{"CR", "a\rb", "contains control byte 0x0d"},
		{"LF", "a\nb", "contains control byte 0x0a"},
		{"CRLF names the first", "a\r\nb", "contains control byte 0x0d"},
		{"unit separator", "a\x1fb", "contains control byte 0x1f"},
		{"invalid UTF-8", "a\xffb", "is not valid UTF-8"},
		{"truncated multi-byte", "a\xe6\x97", "is not valid UTF-8"},
		{"invalid UTF-8 wins over a control byte", "\t\xff", "is not valid UTF-8"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckValue(tc.value)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("CheckValue = %v, want nil", err)
				}
				return
			}
			if err == nil || err.Error() != tc.want {
				t.Fatalf("CheckValue = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestQuoteErrorText(t *testing.T) {
	// Quote reports through CheckValue, so sync and env name a bad value the
	// same way.
	for in, want := range map[string]string{
		"a\tb":   "value contains control byte 0x09",
		"a\xffb": "value is not valid UTF-8",
	} {
		if _, err := Quote(in); err == nil || err.Error() != want {
			t.Errorf("Quote(%q) error = %v, want %q", in, err, want)
		}
	}
}

func TestSelectErrorText(t *testing.T) {
	_, errs := Select(item(
		concealed("f1", "PATH", "x"),
		concealed("f4", "EMPTY", ""),
		concealed("f5", "NL", "a\nb"),
		concealed("f6", "CR", "a\rb"),
		concealed("f7", "TAB", "a\tb"),
		concealed("f8", "ESC", "a\x1bb"),
		concealed("f9", "DEL", "a\x7fb"),
		concealed("f10", "NUL", "a\x00b"),
		concealed("f11", "BAD_UTF", "a\xffb"),
	))
	want := []string{
		`item "Grafana" (item-1): label PATH is denylisted`,
		`item "Grafana" (item-1): EMPTY is empty`,
		`item "Grafana" (item-1): NL contains control byte 0x0a`,
		`item "Grafana" (item-1): CR contains control byte 0x0d`,
		`item "Grafana" (item-1): TAB contains control byte 0x09`,
		`item "Grafana" (item-1): ESC contains control byte 0x1b`,
		`item "Grafana" (item-1): DEL contains control byte 0x7f`,
		`item "Grafana" (item-1): NUL contains control byte 0x00`,
		`item "Grafana" (item-1): BAD_UTF is not valid UTF-8`,
	}
	if len(errs) != len(want) {
		t.Fatalf("errs = %v", errs)
	}
	for i := range want {
		var asErr error = errs[i]
		var se *SelectError
		if !errors.As(asErr, &se) {
			t.Fatalf("errs[%d] is %T, want *SelectError", i, asErr)
		}
		if got := asErr.Error(); got != want[i] {
			t.Errorf("errs[%d] = %q, want %q", i, got, want[i])
		}
	}
}

func TestSelectProvenance(t *testing.T) {
	// A candidate and a problem from one item carry the same full tuple and
	// display strings, differing only in field id and label.
	it := item(concealed("f9", "TOKEN", "v"), concealed("f10", "PATH", "p"))
	cands, errs := Select(it)
	origin := func(field, name string) Origin {
		return Origin{
			Source: bundle.Source{
				AccountUUID: "acct-1", UserUUID: "user-1", VaultID: "vault-1",
				ItemID: "item-1", FieldID: field, Name: name,
			},
			AccountURL: "my.1password.com", VaultName: "Private", ItemTitle: "Grafana",
		}
	}
	if want := []Candidate{{Origin: origin("f9", "TOKEN"), Value: "v"}}; !reflect.DeepEqual(cands, want) {
		t.Errorf("candidates = %+v, want %+v", cands, want)
	}
	if len(errs) != 1 || errs[0].Origin != origin("f10", "PATH") {
		t.Fatalf("errs = %+v", errs)
	}
	wantVar := bundle.Var{
		Name: "TOKEN", Value: "v",
		AccountUUID: "acct-1", UserUUID: "user-1", AccountURL: "my.1password.com",
		VaultID: "vault-1", ItemID: "item-1", FieldID: "f9",
	}
	if got := cands[0].Var(); got != wantVar || got.Source() != cands[0].Source {
		t.Errorf("Var() = %+v, want %+v", got, wantVar)
	}
}

func TestSelectRefusesAnIncompleteSource(t *testing.T) {
	// A source with an empty part could never be trusted or stored.
	tests := map[string]struct {
		mut  func(*Item)
		want string
	}{
		"account": {func(i *Item) { i.AccountUUID = "" }, `item "Grafana" (item-1): TOKEN has no account UUID`},
		"user":    {func(i *Item) { i.UserUUID = "" }, `item "Grafana" (item-1): TOKEN has no user UUID`},
		"vault":   {func(i *Item) { i.VaultID = "" }, `item "Grafana" (item-1): TOKEN has no vault ID`},
		"item":    {func(i *Item) { i.ID = "" }, `item "Grafana" (): TOKEN has no item ID`},
		"field":   {func(i *Item) { i.Fields[0].ID = "" }, `item "Grafana" (item-1): TOKEN has no field ID`},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			it := item(concealed("f1", "TOKEN", "s3cr3t"))
			tc.mut(&it)
			cands, errs := Select(it)
			if len(cands) != 0 || len(errs) != 1 {
				t.Fatalf("candidates = %d, errs = %v", len(cands), errs)
			}
			if got := errs[0].Error(); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
	// Display strings are not identity and may be empty.
	it := item(concealed("f1", "TOKEN", "s3cr3t"))
	it.VaultName, it.Title = "", ""
	if cands, errs := Select(it); len(cands) != 1 || len(errs) != 0 {
		t.Errorf("empty display strings refused: %v", errs)
	}
}

// cands wraps vars as candidates, for the tests that only care about
// identity.
func cands(vars ...bundle.Var) []Candidate {
	out := make([]Candidate, len(vars))
	for i, v := range vars {
		out[i] = Candidate{Origin: Origin{Source: v.Source(), AccountURL: v.AccountURL}, Value: v.Value}
	}
	return out
}

func TestDetectConflicts(t *testing.T) {
	v := func(name, acct, url, itemID string) bundle.Var {
		return bundle.Var{Name: name, Value: "v", AccountUUID: acct, UserUUID: "u-" + acct, AccountURL: url, ItemID: itemID}
	}
	tests := []struct {
		name string
		vars []bundle.Var
		want []string // substrings that must all appear in errs[i]
	}{
		{
			name: "no conflicts",
			vars: []bundle.Var{v("A", "acct1", "my.1password.com", "i1"), v("B", "acct1", "my.1password.com", "i2")},
		},
		{
			name: "within account",
			vars: []bundle.Var{v("TOKEN", "acct1", "my.1password.com", "i1"), v("TOKEN", "acct1", "my.1password.com", "i2")},
			want: []string{"TOKEN i1 my.1password.com i2"},
		},
		{
			name: "across accounts",
			vars: []bundle.Var{v("TOKEN", "acct1", "my.1password.com", "i1"), v("TOKEN", "acct2", "team.1password.com", "i2")},
			want: []string{"TOKEN i1 my.1password.com i2 team.1password.com"},
		},
		{
			name: "sorted by name, three sources",
			vars: []bundle.Var{
				v("Z", "a", "z.1password.com", "z2"),
				v("A", "a", "a.1password.com", "a1"),
				v("Z", "a", "z.1password.com", "z1"),
				v("A", "a", "a.1password.com", "a2"),
				v("Z", "a", "z.1password.com", "z3"),
			},
			want: []string{"A a1 a2", "Z z1 z2 z3"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			errs := DetectConflicts(cands(tc.vars...))
			if len(errs) != len(tc.want) {
				t.Fatalf("errs = %v, want %d", errs, len(tc.want))
			}
			for i, want := range tc.want {
				msg := errs[i].Error()
				if errs[i].Name != strings.Fields(want)[0] || len(errs[i].Sources) < 2 {
					t.Errorf("errs[%d] fields = %+v", i, errs[i])
				}
				for _, w := range strings.Fields(want) {
					if !strings.Contains(msg, w) {
						t.Errorf("errs[%d] = %q, missing %q", i, msg, w)
					}
				}
				if strings.Contains(msg, `"v"`) || strings.Contains(msg, "=v") {
					t.Errorf("errs[%d] leaks value: %q", i, msg)
				}
			}
		})
	}
}

func TestDetectConflictsSameItemTwoFieldsIsConflict(t *testing.T) {
	// Two fields in one item carrying the same label are two sources; the
	// detail must name the field IDs because the item IDs are equal.
	vars := []bundle.Var{
		{Name: "T", AccountUUID: "a", UserUUID: "u", AccountURL: "my.1password.com", ItemID: "i1", FieldID: "f2"},
		{Name: "T", AccountUUID: "a", UserUUID: "u", AccountURL: "my.1password.com", ItemID: "i1", FieldID: "f1"},
	}
	errs := DetectConflicts(cands(vars...))
	if len(errs) != 1 || len(errs[0].Sources) != 2 {
		t.Fatalf("errs = %v, want one conflict with two sources", errs)
	}
	want := "conflict: T is defined by item i1 field f1 (my.1password.com) and item i1 field f2 (my.1password.com)"
	if got := errs[0].Error(); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestDetectConflictsSameSourceDifferentURLIsNotConflict(t *testing.T) {
	// AccountURL is display only: the same (account, user, item, field) seen
	// under two URLs is one source.
	vars := []bundle.Var{
		{Name: "T", AccountUUID: "a", UserUUID: "u", AccountURL: "my.1password.com", ItemID: "i1", FieldID: "f1"},
		{Name: "T", AccountUUID: "a", UserUUID: "u", AccountURL: "my.ent.1password.com", ItemID: "i1", FieldID: "f1"},
	}
	if errs := DetectConflicts(cands(vars...)); len(errs) != 0 {
		t.Fatalf("errs = %v, want none", errs)
	}
}

func TestDetectConflictsKeyedByIdentityNotURL(t *testing.T) {
	// Same URL and item ID, different user: two identities, one conflict.
	// The detail names account and user because the URLs are equal.
	vars := []bundle.Var{
		{Name: "T", AccountUUID: "a", UserUUID: "u1", AccountURL: "my.1password.com", ItemID: "i1", FieldID: "f"},
		{Name: "T", AccountUUID: "a", UserUUID: "u2", AccountURL: "my.1password.com", ItemID: "i1", FieldID: "f"},
	}
	errs := DetectConflicts(cands(vars...))
	if len(errs) != 1 {
		t.Fatalf("errs = %v, want one conflict", errs)
	}
	var asErr error = errs[0]
	var ce *ConflictError
	if !errors.As(asErr, &ce) || ce.Name != "T" || len(ce.Sources) != 2 {
		t.Fatalf("errs[0] = %#v", asErr)
	}
	want := "conflict: T is defined by item i1 field f (my.1password.com account a user u1) and item i1 field f (my.1password.com account a user u2)"
	if got := asErr.Error(); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestDetectConflictsDeterministicOrder(t *testing.T) {
	vars := []bundle.Var{
		{Name: "T", ItemID: "i3", AccountURL: "c"},
		{Name: "T", ItemID: "i1", AccountURL: "a"},
		{Name: "T", ItemID: "i2", AccountURL: "b"},
	}
	first := DetectConflicts(cands(vars...))[0].Error()
	for range 20 {
		if got := DetectConflicts(cands(vars...))[0].Error(); got != first {
			t.Fatalf("nondeterministic: %q vs %q", got, first)
		}
	}
	if i1, i2, i3 := strings.Index(first, "i1"), strings.Index(first, "i2"), strings.Index(first, "i3"); i1 >= i2 || i2 >= i3 {
		t.Errorf("sources not sorted: %q", first)
	}
}

func TestDetectConflictsIgnoresTheVault(t *testing.T) {
	// Conflict identity is (account, user, item, field). The vault is not
	// part of it.
	vars := []bundle.Var{
		{Name: "T", AccountUUID: "a", UserUUID: "u", AccountURL: "my.1password.com", VaultID: "v1", ItemID: "i1", FieldID: "f1"},
		{Name: "T", AccountUUID: "a", UserUUID: "u", AccountURL: "my.1password.com", VaultID: "v2", ItemID: "i1", FieldID: "f1"},
	}
	if errs := DetectConflicts(cands(vars...)); len(errs) != 0 {
		t.Fatalf("errs = %v, want none", errs)
	}
}

// cand builds a complete candidate. item doubles as the account suffix so
// two calls with different items are different sources.
func cand(name, item string) Candidate {
	return Candidate{
		Origin: Origin{
			Source: bundle.Source{
				AccountUUID: "acct", UserUUID: "user", VaultID: "vault",
				ItemID: item, FieldID: "field-" + name, Name: name,
			},
			AccountURL: "my.1password.com", VaultName: "Private", ItemTitle: "Title " + item,
		},
		Value: "s3cr3t-" + name + "-" + item,
	}
}

func prob(name, item, reason string) *SelectError {
	return &SelectError{Origin: cand(name, item).Origin, Reason: reason}
}

// names renders candidates as "NAME@item" so failures never print a value.
func names(cs []Candidate) []string {
	var out []string
	for _, c := range cs {
		out = append(out, c.Source.Name+"@"+c.Source.ItemID)
	}
	return out
}

func probNames(es []*SelectError) []string {
	var out []string
	for _, e := range es {
		out = append(out, e.Source.Name+"@"+e.Source.ItemID)
	}
	return out
}

func conflictNames(es []*ConflictError) []string {
	var out []string
	for _, e := range es {
		out = append(out, e.Name)
	}
	return out
}

func TestSplit(t *testing.T) {
	src := func(name, item string) bundle.Source { return cand(name, item).Source }
	tests := []struct {
		name      string
		cands     []Candidate
		problems  []*SelectError
		trusted   []bundle.Source
		trustedC  []string
		untrusted []string
		trustedP  []string
		untrustP  []string
		conflicts []string
		fatal     bool
	}{
		{name: "nothing"},
		{
			name:      "no trust: everything is untrusted, nothing is fatal",
			cands:     []Candidate{cand("A", "i1"), cand("B", "i1")},
			problems:  []*SelectError{prob("PATH", "i1", "label PATH is denylisted")},
			untrusted: []string{"A@i1", "B@i1"},
			untrustP:  []string{"PATH@i1"},
		},
		{
			name:      "split keeps input order",
			cands:     []Candidate{cand("C", "i1"), cand("A", "i1"), cand("B", "i1"), cand("D", "i1")},
			trusted:   []bundle.Source{src("D", "i1"), src("C", "i1")},
			trustedC:  []string{"C@i1", "D@i1"},
			untrusted: []string{"A@i1", "B@i1"},
		},
		{
			name:      "an untrusted source sharing a trusted name is untrusted, not a conflict",
			cands:     []Candidate{cand("TOKEN", "i1"), cand("TOKEN", "i2")},
			trusted:   []bundle.Source{src("TOKEN", "i1")},
			trustedC:  []string{"TOKEN@i1"},
			untrusted: []string{"TOKEN@i2"},
		},
		{
			name:      "two untrusted sources with one name are both untrusted",
			cands:     []Candidate{cand("TOKEN", "i1"), cand("TOKEN", "i2")},
			untrusted: []string{"TOKEN@i1", "TOKEN@i2"},
		},
		{
			name:      "two trusted sources with one name conflict",
			cands:     []Candidate{cand("TOKEN", "i1"), cand("TOKEN", "i2"), cand("TOKEN", "i3"), cand("OK", "i1")},
			trusted:   []bundle.Source{src("TOKEN", "i1"), src("TOKEN", "i2"), src("OK", "i1")},
			trustedC:  []string{"TOKEN@i1", "TOKEN@i2", "OK@i1"},
			untrusted: []string{"TOKEN@i3"},
			conflicts: []string{"TOKEN"},
			fatal:     true,
		},
		{
			name:     "a problem on a trusted source is fatal",
			cands:    []Candidate{cand("OK", "i1")},
			problems: []*SelectError{prob("TOKEN", "i1", "TOKEN is empty"), prob("PATH", "i2", "label PATH is denylisted")},
			trusted:  []bundle.Source{src("OK", "i1"), src("TOKEN", "i1")},
			trustedC: []string{"OK@i1"},
			trustedP: []string{"TOKEN@i1"},
			untrustP: []string{"PATH@i2"},
			fatal:    true,
		},
		{
			name:     "a problem on an untrusted source sharing a trusted name is not fatal",
			cands:    []Candidate{cand("TOKEN", "i1")},
			problems: []*SelectError{prob("TOKEN", "i2", "TOKEN is empty")},
			trusted:  []bundle.Source{src("TOKEN", "i1")},
			trustedC: []string{"TOKEN@i1"},
			untrustP: []string{"TOKEN@i2"},
		},
		{
			name:     "a trusted source absent from the resolution yields nothing",
			cands:    []Candidate{cand("A", "i1")},
			trusted:  []bundle.Source{src("GONE", "i9"), src("A", "i1")},
			trustedC: []string{"A@i1"},
		},
		{
			name:      "the same source twice is kept once",
			cands:     []Candidate{cand("A", "i1"), cand("A", "i1"), cand("B", "i1"), cand("B", "i1")},
			problems:  []*SelectError{prob("E", "i1", "E is empty"), prob("E", "i1", "E is empty")},
			trusted:   []bundle.Source{src("A", "i1")},
			trustedC:  []string{"A@i1"},
			untrusted: []string{"B@i1"},
			untrustP:  []string{"E@i1"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := Split(tc.cands, tc.problems, tc.trusted)
			for what, pair := range map[string][2][]string{
				"trusted":            {names(p.Trusted), tc.trustedC},
				"untrusted":          {names(p.Untrusted), tc.untrusted},
				"trusted problems":   {probNames(p.TrustedProblems), tc.trustedP},
				"untrusted problems": {probNames(p.UntrustedProblems), tc.untrustP},
				"conflicts":          {conflictNames(p.Conflicts), tc.conflicts},
			} {
				if !reflect.DeepEqual(pair[0], pair[1]) {
					t.Errorf("%s = %v, want %v", what, pair[0], pair[1])
				}
			}
			if p.Fatal() != tc.fatal {
				t.Errorf("Fatal() = %v, want %v", p.Fatal(), tc.fatal)
			}
		})
	}
}

func TestSplitMatchesTheWholeTuple(t *testing.T) {
	c := cand("TOKEN", "i1")
	muts := map[string]func(*bundle.Source){
		"account": func(s *bundle.Source) { s.AccountUUID = "x" },
		"user":    func(s *bundle.Source) { s.UserUUID = "x" },
		"vault":   func(s *bundle.Source) { s.VaultID = "x" },
		"item":    func(s *bundle.Source) { s.ItemID = "x" },
		"field":   func(s *bundle.Source) { s.FieldID = "x" },
		"name":    func(s *bundle.Source) { s.Name = "x" },
	}
	for name, mut := range muts {
		s := c.Source
		mut(&s)
		p := Split([]Candidate{c}, []*SelectError{{Origin: c.Origin, Reason: "r"}}, []bundle.Source{s})
		if len(p.Trusted) != 0 || len(p.Untrusted) != 1 || len(p.TrustedProblems) != 0 || len(p.UntrustedProblems) != 1 {
			t.Errorf("trust that differs in %s still matched", name)
		}
	}
	// Display strings are not identity.
	moved := c
	moved.AccountURL, moved.VaultName, moved.ItemTitle = "other.1password.com", "Renamed", "Renamed"
	if p := Split([]Candidate{moved}, nil, []bundle.Source{c.Source}); len(p.Trusted) != 1 {
		t.Error("a renamed vault, item, or URL lost trust")
	}
}

func TestSplitKeepsOneSourceListedUnderTwoURLs(t *testing.T) {
	// One field listed under two account URLs is one source: the tuples are
	// equal, so it is kept once and never conflicts with itself.
	a := cand("TOKEN", "i1")
	b := a
	b.AccountURL = "my.ent.1password.com"
	p := Split([]Candidate{a, b}, nil, []bundle.Source{a.Source})
	if len(p.Trusted) != 1 || p.Trusted[0].AccountURL != "my.1password.com" || p.Fatal() {
		t.Errorf("trusted = %v, conflicts = %v", names(p.Trusted), conflictNames(p.Conflicts))
	}
}

func TestPartitionVars(t *testing.T) {
	a, b := cand("A", "i1"), cand("B", "i2")
	p := Split([]Candidate{a, b, cand("C", "i3")}, nil, []bundle.Source{b.Source, a.Source})
	got := p.Vars()
	if len(got) != 2 || got[0] != a.Var() || got[1] != b.Var() {
		t.Errorf("Vars() names = %v", names(p.Trusted))
	}
	// The result must be a bundle the encoder accepts.
	if _, err := bundle.Encode(bundle.Bundle{GeneratedAt: time.Unix(1, 0), TrustedSources: []bundle.Source{a.Source, b.Source}, Vars: got}); err != nil {
		t.Errorf("Encode: %v", err)
	}
	if vars := (Partition{}).Vars(); vars == nil || len(vars) != 0 {
		t.Errorf("empty Vars() = %#v, want empty and non-nil", vars)
	}
}

func TestQuote(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"", `''`},
		{"plain", `'plain'`},
		{"with space", `'with space'`},
		{"it's", `'it'\''s'`},
		{"'", `''\'''`},
		{"''", `''\'''\'''`},
		{"$HOME", `'$HOME'`},
		{"`id`", "'`id`'"},
		{`back\slash`, `'back\slash'`},
		{"bang!", `'bang!'`},
		{"héllo wörld ünïcode 日本語 🔑", `'héllo wörld ünïcode 日本語 🔑'`},
		{"a;b|c&d>e<f(g)h{i}j*k?l[m]n#o~p", `'a;b|c&d>e<f(g)h{i}j*k?l[m]n#o~p'`},
	}
	for _, tc := range tests {
		got, err := Quote(tc.in)
		if err != nil {
			t.Errorf("Quote(%q) error: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("Quote(%q) = %s, want %s", tc.in, got, tc.want)
		}
	}
}

func TestQuoteRejects(t *testing.T) {
	tests := map[string]string{
		"NUL":                 "a\x00b",
		"CR":                  "a\rb",
		"LF":                  "a\nb",
		"CRLF":                "a\r\nb",
		"tab":                 "a\tb",
		"BEL":                 "a\x07b",
		"ESC":                 "a\x1bb",
		"unit sep":            "a\x1fb",
		"DEL":                 "a\x7fb",
		"invalid utf8":        "a\xffb",
		"truncated multibyte": "a\xe6\x97",
	}
	for name, in := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := Quote(in)
			if err == nil {
				t.Fatalf("Quote(%q) = %s, want error", in, got)
			}
			if strings.Contains(err.Error(), "a") && strings.Contains(err.Error(), "b") && strings.Contains(err.Error(), in) {
				t.Errorf("error leaks value: %q", err.Error())
			}
		})
	}
}

func TestExportLine(t *testing.T) {
	got, err := ExportLine("GRAFANA_TOKEN", "it's $x")
	if err != nil {
		t.Fatal(err)
	}
	if want := `[[ ${(t)GRAFANA_TOKEN} != *readonly* ]] && builtin unset -- GRAFANA_TOKEN && builtin export -- GRAFANA_TOKEN='it'\''s $x'`; got != want {
		t.Errorf("got %s, want %s", got, want)
	}
	if _, err := ExportLine("GRAFANA_TOKEN", "bad\nvalue"); err == nil {
		t.Error("want error for control byte")
	}
	for _, bad := range []string{"", "lower", "1X", "A B", "A=B", "A\nB"} {
		if _, err := ExportLine(bad, "v"); err == nil {
			t.Errorf("ExportLine(%q) accepted bad name", bad)
		}
	}
}

func TestLine(t *testing.T) {
	if got, want := Line("A", "'v'"), "[[ ${(t)A} != *readonly* ]] && builtin unset -- A && builtin export -- A='v'"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestUnsetLine(t *testing.T) {
	if got, want := UnsetLine("GRAFANA_TOKEN"), "[[ ${(t)GRAFANA_TOKEN} != *readonly* ]] && builtin unset -- GRAFANA_TOKEN"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// runZsh runs script under a fresh zsh with a bounded lifetime.
func runZsh(t *testing.T, script string) []byte {
	t.Helper()
	zsh, err := exec.LookPath("zsh")
	if err != nil {
		t.Skip("zsh not installed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, zsh, "-f", "-c", script)
	cmd.WaitDelay = 2 * time.Second
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("zsh: %v", err)
	}
	return out
}

func TestZshValueNeverExecutes(t *testing.T) {
	if !Denied("PROMPT") {
		t.Fatal("PROMPT must be denylisted: zsh expands it on every prompt")
	}
	markerFile := filepath.Join(t.TempDir(), "marker")
	for _, value := range []string{
		"$(touch " + markerFile + ")",
		"`touch " + markerFile + "`",
		"'; touch " + markerFile + "; '",
	} {
		line, err := ExportLine("ENVSEC_TEST_INJ", value)
		if err != nil {
			t.Fatal(err)
		}
		out := runZsh(t, line+"\nprintf %s \"$ENVSEC_TEST_INJ\"\n")
		if string(out) != value {
			t.Errorf("round trip: got %q, want %q", out, value)
		}
		if _, err := os.Stat(markerFile); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("value %q executed: marker exists (stat err %v)", value, err)
		}
	}
}

// TestZshTypedParameterCannotReinterpretValue predeclares the target with a
// type an attacker (or a dotfile) could have given it and feeds a value that
// would run a command if zsh evaluated it as arithmetic. `path` exists in
// every zsh, so `path[$(...)]` is a live subscript under `typeset -i`.
func TestZshTypedParameterCannotReinterpretValue(t *testing.T) {
	if !Denied("RPROMPT2") {
		t.Fatal("RPROMPT2 must be denylisted: zsh expands it on every prompt")
	}
	markerFile := filepath.Join(t.TempDir(), "marker")
	value := "path[$(touch " + markerFile + ")]"
	line, err := ExportLine("ENVSEC_TEST_TYPED", value)
	if err != nil {
		t.Fatal(err)
	}
	for _, decl := range []string{
		"typeset -i ENVSEC_TEST_TYPED",
		"typeset -a ENVSEC_TEST_TYPED",
		"typeset -A ENVSEC_TEST_TYPED",
	} {
		t.Run(decl, func(t *testing.T) {
			out := runZsh(t, decl+"\n"+line+"\nprintf %s \"$ENVSEC_TEST_TYPED\"\n")
			if _, err := os.Stat(markerFile); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("value executed under %q: marker exists (stat err %v)", decl, err)
			}
			if !bytes.Equal(out, []byte(value)) {
				t.Errorf("round trip under %q: got %q, want %q", decl, out, value)
			}
		})
	}
	t.Run("typeset -r", func(t *testing.T) {
		// The guard skips the line: the value stays, nothing runs, and
		// because unset (a special builtin) never fails, the enclosing eval
		// continues to the next line. The line is eval'd here because that
		// is how the loader runs and an aborted eval would hide the bug.
		quotedLine, err := Quote(line + "; builtin export -- ENVSEC_TEST_AFTER=ran")
		if err != nil {
			t.Fatal(err)
		}
		out := runZsh(t, "typeset -r ENVSEC_TEST_TYPED=orig\neval "+quotedLine+"\nprintf %s \"$ENVSEC_TEST_TYPED $ENVSEC_TEST_AFTER\"\n")
		if _, err := os.Stat(markerFile); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("value executed under readonly: marker exists (stat err %v)", err)
		}
		if string(out) != "orig ran" {
			t.Errorf("got %q, want %q (readonly unchanged, eval continued)", out, "orig ran")
		}
	})
	t.Run("typeset -r stale unset", func(t *testing.T) {
		quoted, err := Quote(UnsetLine("ENVSEC_TEST_TYPED") + "; builtin export -- ENVSEC_TEST_AFTER=ran")
		if err != nil {
			t.Fatal(err)
		}
		out := runZsh(t, "typeset -r ENVSEC_TEST_TYPED=orig\neval "+quoted+"\nprintf %s \"$ENVSEC_TEST_TYPED $ENVSEC_TEST_AFTER\"\n")
		if string(out) != "orig ran" {
			t.Errorf("got %q, want %q", out, "orig ran")
		}
	})
	t.Run("readonly detected by every type", func(t *testing.T) {
		for _, decl := range []string{"typeset -r X=1", "typeset -ri X=1", "typeset -ra X=(1)", "typeset -rA X=(k v)"} {
			out := runZsh(t, decl+"\nprintf %s \"${(t)X}\"\n")
			if !strings.Contains(string(out), "readonly") {
				t.Errorf("%s: (t) = %q lacks readonly", decl, out)
			}
		}
	})
}

func TestExportLineZshRoundTrip(t *testing.T) {
	values := []string{
		"plain",
		"",
		"it's a 'quoted' value",
		"'",
		`$HOME ${HOME} $(id) ` + "`id`",
		`back\slash \n literal \\ two`,
		"bang! and !! history",
		"héllo 日本語 🔑",
		"a;b|c&d>e<f(g)h{i}j*k?l[m]n#o~p%q^r",
		"  leading and trailing  ",
		"~/path",
	}
	for _, value := range values {
		t.Run(value, func(t *testing.T) {
			line, err := ExportLine("ENVSEC_TEST_RT", value)
			if err != nil {
				t.Fatal(err)
			}
			out := runZsh(t, line+"\nprintf %s \"$ENVSEC_TEST_RT\"\n")
			if !bytes.Equal(out, []byte(value)) {
				t.Errorf("round trip: got %q, want %q (line %s)", out, value, line)
			}
		})
	}
}
