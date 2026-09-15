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
				names = append(names, v.Name)
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
				if errs[i].Label != want || errs[i].ItemID != tc.item.ID || errs[i].ItemTitle != tc.item.Title || errs[i].Reason == "" {
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

func TestSelectErrorText(t *testing.T) {
	_, errs := Select(item(
		concealed("f1", "PATH", "x"),
		concealed("f4", "EMPTY", ""),
		concealed("f5", "NL", "a\nb"),
	))
	want := []string{
		`item "Grafana" (item-1): label PATH is denylisted`,
		`item "Grafana" (item-1): EMPTY is empty`,
		`item "Grafana" (item-1): NL contains a newline`,
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
	it := item(concealed("f9", "TOKEN", "v"))
	vars, errs := Select(it)
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	want := []bundle.Var{{
		Name: "TOKEN", Value: "v",
		AccountUUID: "acct-1", UserUUID: "user-1", AccountURL: "my.1password.com",
		ItemID: "item-1", FieldID: "f9",
	}}
	if !reflect.DeepEqual(vars, want) {
		t.Errorf("vars = %+v, want %+v", vars, want)
	}
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
			errs := DetectConflicts(tc.vars)
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
	errs := DetectConflicts(vars)
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
	if errs := DetectConflicts(vars); len(errs) != 0 {
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
	errs := DetectConflicts(vars)
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
	first := DetectConflicts(vars)[0].Error()
	for range 20 {
		if got := DetectConflicts(vars)[0].Error(); got != first {
			t.Fatalf("nondeterministic: %q vs %q", got, first)
		}
	}
	if i1, i2, i3 := strings.Index(first, "i1"), strings.Index(first, "i2"), strings.Index(first, "i3"); i1 >= i2 || i2 >= i3 {
		t.Errorf("sources not sorted: %q", first)
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
