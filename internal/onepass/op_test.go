package onepass

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// fixture reads testdata/<name>.
func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// cannedRun records the invocation and returns fixed output.
type cannedRun struct {
	stdout, stderr []byte
	exitCode       int
	err            error
	gotName        string
	gotArgs        []string
}

func (c *cannedRun) run(_ context.Context, name string, args ...string) ([]byte, []byte, int, error) {
	c.gotName = name
	c.gotArgs = args
	return c.stdout, c.stderr, c.exitCode, c.err
}

var (
	acct1 = Account{URL: "my.1password.com", Email: "user@example.com", UserUUID: "USERUUID000000000000000001", AccountUUID: "ACCTUUID000000000000000001"}
	acct2 = Account{URL: "example.1password.com", Email: "user@example.com", UserUUID: "USERUUID000000000000000002", AccountUUID: "ACCTUUID000000000000000002"}
)

func TestAccounts(t *testing.T) {
	run := &cannedRun{stdout: fixture(t, "account_list.json")}
	c := New(Options{Runner: run.run})

	got, err := c.Accounts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := []Account{acct1, acct2}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("accounts = %+v, want %+v", got, want)
	}
	if run.gotName != "op" {
		t.Errorf("name = %q, want op", run.gotName)
	}
	wantArgs := []string{"account", "list", "--format", "json"}
	if !reflect.DeepEqual(run.gotArgs, wantArgs) {
		t.Errorf("args = %q, want %q", run.gotArgs, wantArgs)
	}
}

func TestListTagged(t *testing.T) {
	tests := []struct {
		name   string
		stdout []byte
		want   []Item
	}{
		{
			name:   "two summaries",
			stdout: fixture(t, "item_list.json"),
			want: []Item{
				{
					ID: "ITEMID0000000000000000000001", Title: "Grafana API token",
					Vault: Vault{ID: "VAULTID000000000000000000001", Name: "Private"},
					Tags:  []string{"shell-env", "infra"},
				},
				{
					ID: "ITEMID0000000000000000000002", Title: "Old login",
					Vault: Vault{ID: "VAULTID000000000000000000001", Name: "Private"},
				},
			},
		},
		{name: "empty array", stdout: fixture(t, "item_list_empty.json"), want: []Item{}},
		{name: "no output", stdout: nil, want: []Item{}},
		{name: "whitespace only", stdout: []byte("\n"), want: []Item{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			run := &cannedRun{stdout: tt.stdout}
			c := New(Options{Runner: run.run})

			got, err := c.ListTagged(context.Background(), acct2, "shell-env")
			if err != nil {
				t.Fatal(err)
			}
			if got == nil {
				t.Fatal("got nil slice, want empty non-nil")
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("items = %+v, want %+v", got, tt.want)
			}
			for _, it := range got {
				if it.Fields != nil {
					t.Errorf("summary %s has fields", it.ID)
				}
			}
			wantArgs := []string{"item", "list", "--tags", "shell-env", "--format", "json", "--account", acct2.AccountUUID}
			if !reflect.DeepEqual(run.gotArgs, wantArgs) {
				t.Errorf("args = %q, want %q", run.gotArgs, wantArgs)
			}
		})
	}
}

func TestGetItem(t *testing.T) {
	run := &cannedRun{stdout: fixture(t, "item_get.json")}
	c := New(Options{Runner: run.run})

	got, err := c.GetItem(context.Background(), acct1, "ITEMID0000000000000000000001")
	if err != nil {
		t.Fatal(err)
	}
	want := Item{
		ID: "ITEMID0000000000000000000001", Title: "Grafana API token",
		Vault: Vault{ID: "VAULTID000000000000000000001", Name: "Private"},
		Tags:  []string{"shell-env", "infra"},
		Fields: []Field{
			{ID: "username", Type: "STRING", Label: "username", Value: "svc-grafana"},
			{ID: "credential", Type: "CONCEALED", Label: "GRAFANA_TOKEN", Value: "synthetic-value-0001"},
			{ID: "notesPlain", Type: "STRING", Label: "notesPlain"},
			{ID: "hostname", Type: "URL", Label: "hostname", Value: "https://grafana.example.com"},
			{ID: "unlabeled", Type: "CONCEALED", Value: "synthetic-value-0002"},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("item = %+v, want %+v", got, want)
	}
	wantArgs := []string{"item", "get", "ITEMID0000000000000000000001", "--format", "json", "--reveal", "--account", acct1.AccountUUID}
	if !reflect.DeepEqual(run.gotArgs, wantArgs) {
		t.Errorf("args = %q, want %q", run.gotArgs, wantArgs)
	}
}

func TestGetItemNotFound(t *testing.T) {
	for _, stderr := range []string{
		`[ERROR] 2026/09/14 10:00:00 "nope" isn't an item. Specify the item with its UUID, name, or domain.`,
		`[ERROR] 2026/09/14 10:00:00 item not found`,
	} {
		run := &cannedRun{stderr: []byte(stderr), exitCode: 1}
		c := New(Options{Runner: run.run})
		_, err := c.GetItem(context.Background(), acct1, "nope")
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("stderr %q: err = %v, want ErrNotFound", stderr, err)
		}
	}
}

func TestAuthErrorClassification(t *testing.T) {
	tests := []struct {
		stderr string
		auth   bool
	}{
		{"[ERROR] 2026/09/14 10:00:00 You are not currently signed in. Please run `op signin --help` for instructions", true},
		{"[ERROR] not signed in", true},
		{"[ERROR] authorization prompt dismissed, please try again", true},
		{"[ERROR] Session expired, please sign in again", true},
		{"[ERROR] Touch ID authentication failed", true},
		{"[ERROR] could not unlock account", true},
		{"[ERROR] No accounts configured for use with 1Password CLI", true},
		{"[ERROR] 2026/09/14 10:00:00 unknown flag: --bogus\nUsage: op item list", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.stderr, func(t *testing.T) {
			run := &cannedRun{stderr: []byte(tt.stderr), exitCode: 1}
			c := New(Options{Runner: run.run})

			_, err := c.ListTagged(context.Background(), acct2, "shell-env")
			if err == nil {
				t.Fatal("want error")
			}
			var ae *AuthError
			if got := errors.As(err, &ae); got != tt.auth {
				t.Fatalf("AuthError = %v, want %v (err %v)", got, tt.auth, err)
			}
			if tt.auth {
				if ae.Account != acct2 {
					t.Errorf("AuthError.Account = %+v, want %+v", ae.Account, acct2)
				}
				if ae.Detail == "" {
					t.Error("AuthError.Detail empty")
				}
				return
			}
			var ce *CommandError
			if !errors.As(err, &ce) {
				t.Fatalf("want CommandError, got %T %v", err, err)
			}
			if ce.ExitCode != 1 {
				t.Errorf("ExitCode = %d, want 1", ce.ExitCode)
			}
			if strings.Contains(ce.Detail, "\n") {
				t.Errorf("Detail spans lines: %q", ce.Detail)
			}
			if tt.stderr != "" && !strings.Contains(ce.Detail, "unknown flag") {
				t.Errorf("Detail = %q, want first stderr line", ce.Detail)
			}
		})
	}
}

func TestAccountsAuthErrorHasZeroAccount(t *testing.T) {
	run := &cannedRun{stderr: []byte("[ERROR] no accounts configured"), exitCode: 1}
	c := New(Options{Runner: run.run})
	_, err := c.Accounts(context.Background())
	var ae *AuthError
	if !errors.As(err, &ae) {
		t.Fatalf("want AuthError, got %v", err)
	}
	if ae.Account != (Account{}) {
		t.Errorf("Account = %+v, want zero", ae.Account)
	}
}

func TestTimeout(t *testing.T) {
	block := func(ctx context.Context, _ string, _ ...string) ([]byte, []byte, int, error) {
		<-ctx.Done()
		return nil, nil, -1, ctx.Err()
	}
	c := New(Options{Runner: block, Timeout: 20 * time.Millisecond})

	start := time.Now()
	_, err := c.Accounts(context.Background())
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("err = %v, want ErrTimeout", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Error("timeout not applied")
	}
}

func TestParentCancelIsNotTimeout(t *testing.T) {
	block := func(ctx context.Context, _ string, _ ...string) ([]byte, []byte, int, error) {
		<-ctx.Done()
		return nil, nil, -1, ctx.Err()
	}
	c := New(Options{Runner: block})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := c.Accounts(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if errors.Is(err, ErrTimeout) {
		t.Error("cancel reported as timeout")
	}
}

func TestRunnerFailure(t *testing.T) {
	run := &cannedRun{err: errors.New("exec: \"op\": executable file not found in $PATH"), exitCode: -1}
	c := New(Options{Runner: run.run})
	_, err := c.Accounts(context.Background())
	if err == nil || !strings.Contains(err.Error(), "not found in $PATH") {
		t.Fatalf("err = %v", err)
	}
}

func TestBadJSON(t *testing.T) {
	run := &cannedRun{stdout: []byte("{not json")}
	c := New(Options{Runner: run.run})
	if _, err := c.Accounts(context.Background()); err == nil {
		t.Error("Accounts: want error")
	}
	if _, err := c.ListTagged(context.Background(), acct1, "t"); err == nil {
		t.Error("ListTagged: want error")
	}
	if _, err := c.GetItem(context.Background(), acct1, "x"); err == nil {
		t.Error("GetItem: want error")
	}
}

func TestVerboseStderr(t *testing.T) {
	for _, verbose := range []bool{true, false} {
		var buf bytes.Buffer
		run := &cannedRun{stdout: fixture(t, "account_list.json"), stderr: []byte("op: some warning\n")}
		c := New(Options{Runner: run.run, Verbose: verbose, Stderr: &buf})
		if _, err := c.Accounts(context.Background()); err != nil {
			t.Fatal(err)
		}
		if got := strings.Contains(buf.String(), "some warning"); got != verbose {
			t.Errorf("verbose=%v: stderr forwarded=%v (%q)", verbose, got, buf.String())
		}
	}
}

func TestPathOption(t *testing.T) {
	run := &cannedRun{stdout: []byte("[]")}
	c := New(Options{Runner: run.run, Path: "/opt/bin/op"})
	if _, err := c.Accounts(context.Background()); err != nil {
		t.Fatal(err)
	}
	if run.gotName != "/opt/bin/op" {
		t.Errorf("name = %q", run.gotName)
	}
}

// TestExecRunner exercises the real subprocess runner with sh, never op.
func TestExecRunner(t *testing.T) {
	ctx := context.Background()
	stdout, stderr, code, err := execRunner(ctx, "sh", "-c", "echo out; echo err >&2; exit 3")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if string(stdout) != "out\n" || string(stderr) != "err\n" || code != 3 {
		t.Errorf("stdout=%q stderr=%q code=%d", stdout, stderr, code)
	}

	stdout, _, code, err = execRunner(ctx, "sh", "-c", "echo ok")
	if err != nil || code != 0 || string(stdout) != "ok\n" {
		t.Errorf("success run: stdout=%q code=%d err=%v", stdout, code, err)
	}

	tctx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	_, _, _, err = execRunner(tctx, "sh", "-c", "sleep 5")
	if err == nil {
		t.Error("timed-out run: want error")
	}

	_, _, _, err = execRunner(ctx, "/nonexistent/op")
	if err == nil {
		t.Error("missing binary: want error")
	}
}

func TestExecRunnerTimeoutMapsToErrTimeout(t *testing.T) {
	c := New(Options{Path: "sh", Timeout: 50 * time.Millisecond, Runner: func(ctx context.Context, _ string, _ ...string) ([]byte, []byte, int, error) {
		return execRunner(ctx, "sh", "-c", "sleep 5")
	}})
	_, err := c.Accounts(context.Background())
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("err = %v, want ErrTimeout", err)
	}
}

func TestHasTag(t *testing.T) {
	it := Item{Tags: []string{"shell-env", "Infra"}}
	tests := []struct {
		tag  string
		want bool
	}{
		{"shell-env", true},
		{"Shell-Env", false},
		{"infra", false},
		{"Infra", true},
		{"", false},
	}
	for _, tt := range tests {
		if got := HasTag(it, tt.tag); got != tt.want {
			t.Errorf("HasTag(%q) = %v, want %v", tt.tag, got, tt.want)
		}
	}
	if HasTag(Item{}, "shell-env") {
		t.Error("untagged item matched")
	}
}
