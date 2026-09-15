package onepass

import (
	"bytes"
	"context"
	"errors"
	"fmt"
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
		{"[ERROR] authentication required", true},
		{"[ERROR] account is locked", true},
		{"[ERROR] 2026/09/14 10:00:00 unknown flag: --bogus\nUsage: op item list", false},
		{"[ERROR] 2026/09/14 10:00:00 error initializing client: connection refused", false},
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
			if first, _, _ := strings.Cut(tt.stderr, "\n"); ce.Detail != first {
				t.Errorf("Detail = %q, want first stderr line %q", ce.Detail, first)
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
	// An unanswered prompt is indistinguishable from a lock: exit 2.
	var ae *AuthError
	if !errors.As(err, &ae) {
		t.Fatalf("err = %v, want AuthError", err)
	}
	if want := "op timed out after 20ms; a Touch ID or unlock prompt was probably unanswered"; ae.Detail != want {
		t.Errorf("Detail = %q, want %q", ae.Detail, want)
	}
}

func TestTimeoutWithAuthMarkerKeepsStderrDetailForListCommands(t *testing.T) {
	block := func(ctx context.Context, _ string, _ ...string) ([]byte, []byte, int, error) {
		<-ctx.Done()
		return nil, []byte("[ERROR] You are not currently signed in.\nmore\n"), -1, ctx.Err()
	}
	c := New(Options{Runner: block, Timeout: 20 * time.Millisecond})
	for name, call := range map[string]func() error{
		"account list": func() error { _, err := c.Accounts(context.Background()); return err },
		"item list":    func() error { _, err := c.ListTagged(context.Background(), acct2, "shell-env"); return err },
	} {
		t.Run(name, func(t *testing.T) {
			err := call()
			var ae *AuthError
			if !errors.As(err, &ae) {
				t.Fatalf("err = %v, want AuthError", err)
			}
			if ae.Detail != "[ERROR] You are not currently signed in." {
				t.Errorf("Detail = %q", ae.Detail)
			}
			if !errors.Is(err, ErrTimeout) {
				t.Error("timeout not reported through errors.Is")
			}
		})
	}
}

func TestItemGetTimeoutNeverCarriesStderr(t *testing.T) {
	const leak = "LEAKED-STDERR-TEXT"
	block := func(ctx context.Context, _ string, _ ...string) ([]byte, []byte, int, error) {
		<-ctx.Done()
		return nil, []byte("[ERROR] You are not currently signed in. " + leak + "\n"), -1, ctx.Err()
	}
	c := New(Options{Runner: block, Timeout: 20 * time.Millisecond})
	_, err := c.GetItem(context.Background(), acct1, "x")
	var ae *AuthError
	if !errors.As(err, &ae) || !errors.Is(err, ErrTimeout) {
		t.Fatalf("err = %v, want AuthError wrapping ErrTimeout", err)
	}
	if want := "op timed out after 20ms; a Touch ID or unlock prompt was probably unanswered"; ae.Detail != want {
		t.Errorf("Detail = %q, want %q", ae.Detail, want)
	}
	if strings.Contains(err.Error(), leak) {
		t.Errorf("error carries item get stderr: %q", err.Error())
	}
}

func TestItemGetAuthErrorHasFixedDetail(t *testing.T) {
	const leak = "LEAKED-STDERR-TEXT"
	run := &cannedRun{stderr: []byte("[ERROR] You are not currently signed in. " + leak + "\n"), exitCode: 1}
	c := New(Options{Runner: run.run})
	_, err := c.GetItem(context.Background(), acct1, "x")
	var ae *AuthError
	if !errors.As(err, &ae) {
		t.Fatalf("err = %v, want AuthError", err)
	}
	if ae.Detail != "op item get exited 1 with an authorization error" || ae.Account != acct1 {
		t.Errorf("AuthError = %+v", ae)
	}
	if strings.Contains(err.Error(), leak) {
		t.Errorf("error carries item get stderr: %q", err.Error())
	}
}

func TestItemGetRunnerErrorHasFixedText(t *testing.T) {
	const leak = "LEAKED-RUNNER-TEXT"
	run := &cannedRun{err: errors.New("wrapper: " + leak), exitCode: -1}
	c := New(Options{Runner: run.run})
	_, err := c.GetItem(context.Background(), acct1, "x")
	if err == nil {
		t.Fatal("want error")
	}
	if strings.Contains(err.Error(), leak) {
		t.Errorf("error carries runner text: %q", err.Error())
	}
	if want := "op item get could not run"; err.Error() != want {
		t.Errorf("err = %q, want %q", err.Error(), want)
	}
}

func TestItemGetParentCancelStillReported(t *testing.T) {
	block := func(ctx context.Context, _ string, _ ...string) ([]byte, []byte, int, error) {
		<-ctx.Done()
		return nil, nil, -1, ctx.Err()
	}
	c := New(Options{Runner: block})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := c.GetItem(ctx, acct1, "x")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

func TestAccountsEmptyIsAuthError(t *testing.T) {
	for _, stdout := range []string{"[]", "[]\n"} {
		run := &cannedRun{stdout: []byte(stdout)}
		c := New(Options{Runner: run.run})
		_, err := c.Accounts(context.Background())
		var ae *AuthError
		if !errors.As(err, &ae) {
			t.Fatalf("stdout %q: err = %v, want AuthError", stdout, err)
		}
		if ae.Detail != "no 1Password accounts are signed in" || ae.Account != (Account{}) {
			t.Errorf("AuthError = %+v", ae)
		}
	}
}

func TestDecodeRejectsBlankAndNull(t *testing.T) {
	for _, stdout := range []string{"", "\n", "  \n", "null", "null\n"} {
		run := &cannedRun{stdout: []byte(stdout)}
		c := New(Options{Runner: run.run})
		if _, err := c.Accounts(context.Background()); err == nil || !strings.Contains(err.Error(), "malformed output") {
			t.Errorf("Accounts(%q): err = %v, want malformed output", stdout, err)
		}
		if _, err := c.ListTagged(context.Background(), acct1, "t"); err == nil || !strings.Contains(err.Error(), "malformed output") {
			t.Errorf("ListTagged(%q): err = %v, want malformed output", stdout, err)
		}
		if _, err := c.GetItem(context.Background(), acct1, "x"); err == nil || !strings.Contains(err.Error(), "malformed output") {
			t.Errorf("GetItem(%q): err = %v, want malformed output", stdout, err)
		}
	}
}

func TestAccountsValidation(t *testing.T) {
	for name, stdout := range map[string]string{
		"missing account_uuid": `[{"url":"my.1password.com","email":"u@example.com","user_uuid":"U1"}]`,
		"empty user_uuid":      `[{"url":"my.1password.com","email":"u@example.com","user_uuid":"","account_uuid":"A1"}]`,
	} {
		t.Run(name, func(t *testing.T) {
			run := &cannedRun{stdout: []byte(stdout)}
			c := New(Options{Runner: run.run})
			_, err := c.Accounts(context.Background())
			if err == nil {
				t.Fatal("want error")
			}
			var ae *AuthError
			if errors.As(err, &ae) {
				t.Fatalf("validation failure classified as auth: %v", err)
			}
		})
	}
}

func TestListTaggedRejectsEmptyID(t *testing.T) {
	run := &cannedRun{stdout: []byte(`[{"id":"","title":"x","tags":["shell-env"]}]`)}
	c := New(Options{Runner: run.run})
	if _, err := c.ListTagged(context.Background(), acct1, "shell-env"); err == nil || !strings.Contains(err.Error(), "empty id") {
		t.Fatalf("err = %v, want empty id", err)
	}
}

func TestGetItemIDMismatch(t *testing.T) {
	run := &cannedRun{stdout: fixture(t, "item_get.json")}
	c := New(Options{Runner: run.run})
	_, err := c.GetItem(context.Background(), acct1, "ITEMID0000000000000000000009")
	if err == nil || !strings.Contains(err.Error(), "item id mismatch") {
		t.Fatalf("err = %v, want item id mismatch", err)
	}
	run = &cannedRun{stdout: []byte(`{"title":"no id","fields":[]}`)}
	c = New(Options{Runner: run.run})
	if _, err := c.GetItem(context.Background(), acct1, "x"); err == nil || !strings.Contains(err.Error(), "item id mismatch") {
		t.Fatalf("empty id: err = %v, want item id mismatch", err)
	}
}

func TestGetItemNotFoundWinsOverAuthMarker(t *testing.T) {
	run := &cannedRun{stderr: []byte(`[ERROR] "nope" isn't an item. unlock the vault and retry`), exitCode: 1}
	c := New(Options{Runner: run.run})
	_, err := c.GetItem(context.Background(), acct1, "nope")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	var ae *AuthError
	if errors.As(err, &ae) {
		t.Fatal("not-found classified as auth")
	}
}

func TestGetItemCommandErrorRedactsStderr(t *testing.T) {
	const leak = "LEAKED-STDERR-TEXT"
	run := &cannedRun{stderr: []byte("[ERROR] boom " + leak + "\n"), exitCode: 3}
	c := New(Options{Runner: run.run})
	_, err := c.GetItem(context.Background(), acct1, "x")
	var ce *CommandError
	if !errors.As(err, &ce) {
		t.Fatalf("err = %T %v, want CommandError", err, err)
	}
	if ce.Detail != "op item get exited 3" {
		t.Errorf("Detail = %q", ce.Detail)
	}
	if strings.Contains(err.Error(), leak) {
		t.Errorf("error carries item get stderr: %q", err.Error())
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
			t.Errorf("verbose=%v: account list stderr forwarded=%v (%q)", verbose, got, buf.String())
		}

		buf.Reset()
		run = &cannedRun{stdout: fixture(t, "item_list.json"), stderr: []byte("op: list warning\n")}
		c = New(Options{Runner: run.run, Verbose: verbose, Stderr: &buf})
		if _, err := c.ListTagged(context.Background(), acct1, "shell-env"); err != nil {
			t.Fatal(err)
		}
		if got := strings.Contains(buf.String(), "list warning"); got != verbose {
			t.Errorf("verbose=%v: item list stderr forwarded=%v (%q)", verbose, got, buf.String())
		}
	}
}

func TestVerboseNeverForwardsItemGetStderr(t *testing.T) {
	const leak = "LEAKED-STDERR-TEXT"
	for name, run := range map[string]*cannedRun{
		"success": {stdout: fixture(t, "item_get.json"), stderr: []byte("op: " + leak + "\n")},
		"failure": {stderr: []byte("[ERROR] boom " + leak + "\n"), exitCode: 3},
	} {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			c := New(Options{Runner: run.run, Verbose: true, Stderr: &buf})
			_, _ = c.GetItem(context.Background(), acct1, "ITEMID0000000000000000000001")
			if buf.Len() != 0 {
				t.Errorf("item get stderr forwarded: %q", buf.String())
			}
		})
	}
}

func TestDecodeRejectsInvalidUTF8(t *testing.T) {
	bad := []byte("[{\"url\":\"my.1password.com\",\"email\":\"u\",\"user_uuid\":\"U\",\"account_uuid\":\"A\xff\"}]")
	run := &cannedRun{stdout: bad}
	c := New(Options{Runner: run.run})
	if _, err := c.Accounts(context.Background()); err == nil || !strings.Contains(err.Error(), "malformed output") {
		t.Errorf("Accounts: err = %v, want malformed output", err)
	}
	run = &cannedRun{stdout: []byte("{\"id\":\"x\",\"tags\":[],\"fields\":[{\"id\":\"f\",\"value\":\"\xff\"}]}")}
	c = New(Options{Runner: run.run})
	if _, err := c.GetItem(context.Background(), acct1, "x"); err == nil || !strings.Contains(err.Error(), "malformed output") {
		t.Errorf("GetItem: err = %v, want malformed output", err)
	}
}

func TestGetItemStrictShape(t *testing.T) {
	cases := map[string]struct {
		stdout string
		want   string // substring of the error; empty means success
	}{
		"tags and fields empty arrays": {`{"id":"x","title":"t","tags":[],"fields":[]}`, ""},
		"tags missing":                 {`{"id":"x","title":"t","fields":[]}`, "tags"},
		"tags null":                    {`{"id":"x","title":"t","tags":null,"fields":[]}`, "tags"},
		"fields missing":               {`{"id":"x","title":"t","tags":["shell-env"]}`, "fields"},
		"fields null":                  {`{"id":"x","title":"t","tags":["shell-env"],"fields":null}`, "fields"},
		"field with empty id":          {`{"id":"x","title":"t","tags":[],"fields":[{"id":"","type":"CONCEALED","label":"A","value":"v"}]}`, "empty id"},
		"field without id":             {`{"id":"x","title":"t","tags":[],"fields":[{"type":"CONCEALED","label":"A","value":"v"}]}`, "empty id"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			run := &cannedRun{stdout: []byte(tc.stdout)}
			c := New(Options{Runner: run.run})
			item, err := c.GetItem(context.Background(), acct1, "x")
			if tc.want == "" {
				if err != nil {
					t.Fatalf("err = %v", err)
				}
				if item.Tags == nil || item.Fields == nil {
					t.Fatalf("empty arrays decoded as nil: %+v", item)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want mention of %q", err, tc.want)
			}
			var ae *AuthError
			if errors.As(err, &ae) {
				t.Fatal("shape failure classified as auth")
			}
		})
	}
}

func TestAccountsStrictShape(t *testing.T) {
	one := `{"url":"my.1password.com","email":"u@example.com","user_uuid":"U1","account_uuid":"A1"}`
	cases := map[string]string{
		"empty url":          `[{"url":"","email":"u@example.com","user_uuid":"U1","account_uuid":"A1"}]`,
		"missing url":        `[{"email":"u@example.com","user_uuid":"U1","account_uuid":"A1"}]`,
		"duplicate identity": `[` + one + `,{"url":"other.1password.com","email":"u@example.com","user_uuid":"U1","account_uuid":"A1"}]`,
	}
	for name, stdout := range cases {
		t.Run(name, func(t *testing.T) {
			run := &cannedRun{stdout: []byte(stdout)}
			c := New(Options{Runner: run.run})
			_, err := c.Accounts(context.Background())
			if err == nil {
				t.Fatal("want error")
			}
			var ae *AuthError
			if errors.As(err, &ae) {
				t.Fatalf("shape failure classified as auth: %v", err)
			}
		})
	}
	// Same account UUID with two users is two identities, not a duplicate.
	run := &cannedRun{stdout: []byte(`[` + one + `,{"url":"my.1password.com","email":"o@example.com","user_uuid":"U2","account_uuid":"A1"}]`)}
	c := New(Options{Runner: run.run})
	if got, err := c.Accounts(context.Background()); err != nil || len(got) != 2 {
		t.Fatalf("two users under one account: got %d accounts, err %v", len(got), err)
	}
}

func TestListTaggedRejectsDuplicateIDs(t *testing.T) {
	run := &cannedRun{stdout: []byte(`[{"id":"x","title":"a","tags":["shell-env"]},{"id":"x","title":"b","tags":["shell-env"]}]`)}
	c := New(Options{Runner: run.run})
	if _, err := c.ListTagged(context.Background(), acct1, "shell-env"); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("err = %v, want duplicate", err)
	}
}

// TestExecRunnerScrubsManagedVars re-executes the test binary as the child
// (the GO_WANT_HELPER_PROCESS pattern) and reads back the environment the
// default runner handed it: the sentinel and every valid name it lists are
// gone, everything else survives.
func TestExecRunnerScrubsManagedVars(t *testing.T) {
	t.Setenv("GO_WANT_HELPER_PROCESS", "1")
	t.Setenv("ENVSEC_MANAGED_VARS", "GRAFANA_TOKEN OTHER_TOKEN lower-case PATH")
	t.Setenv("GRAFANA_TOKEN", "g")
	t.Setenv("OTHER_TOKEN", "o")
	t.Setenv("lower-case", "l")
	t.Setenv("ENVSEC_KEEP_TEST", "k")
	t.Setenv("UNRELATED_TOKEN", "u")
	pathBefore := os.Getenv("PATH")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	stdout, stderr, code, err := execRunner(ctx, os.Args[0], "-test.run=^TestHelperProcess$", "--")
	if err != nil || code != 0 {
		t.Fatalf("helper: code=%d err=%v stderr=%s", code, err, stderr)
	}
	env := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(stdout)), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			env[k] = v
		}
	}
	for _, gone := range []string{"ENVSEC_MANAGED_VARS", "GRAFANA_TOKEN", "OTHER_TOKEN"} {
		if v, ok := env[gone]; ok {
			t.Errorf("%s reached the child (=%q)", gone, v)
		}
	}
	for k, want := range map[string]string{"lower-case": "l", "ENVSEC_KEEP_TEST": "k", "UNRELATED_TOKEN": "u", "PATH": pathBefore} {
		if got := env[k]; got != want {
			t.Errorf("%s = %q in the child, want %q", k, got, want)
		}
	}
}

// TestHelperProcess is the child for TestExecRunnerScrubsManagedVars. It is
// a no-op unless GO_WANT_HELPER_PROCESS is set.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	defer os.Exit(0)
	for _, kv := range os.Environ() {
		fmt.Println(kv)
	}
}

func TestPathOption(t *testing.T) {
	run := &cannedRun{stdout: fixture(t, "account_list.json")}
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
