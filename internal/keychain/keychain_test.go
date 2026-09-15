package keychain

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// call records one invocation seen by the fake runner.
type call struct {
	name string
	args []string
}

// scripted returns a Runner that records calls and replays a fixed result.
func scripted(calls *[]call, stdout, stderr string, exitCode int, err error) Runner {
	return func(_ context.Context, name string, args ...string) ([]byte, []byte, int, error) {
		*calls = append(*calls, call{name: name, args: args})
		return []byte(stdout), []byte(stderr), exitCode, err
	}
}

// tempKeychain creates an empty file standing in for login.keychain-db.
func tempKeychain(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "login.keychain-db")
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDefaults(t *testing.T) {
	s := New(Options{}).(*store)
	home, _ := os.UserHomeDir()
	want := Options{
		KeychainPath: filepath.Join(home, "Library", "Keychains", "login.keychain-db"),
		Service:      "envsec",
		Account:      "bundle",
		SecurityPath: "/usr/bin/security",
		Timeout:      10 * time.Second,
	}
	got := s.opts
	got.Run = nil
	if !reflect.DeepEqual(got, want) {
		t.Errorf("defaults:\n got %+v\nwant %+v", got, want)
	}
	if s.opts.Run == nil {
		t.Error("default Run is nil")
	}
}

func TestReadArgs(t *testing.T) {
	kc := tempKeychain(t)
	var calls []call
	s := New(Options{
		KeychainPath: kc,
		Service:      "svc",
		Account:      "acct",
		SecurityPath: "/opt/security",
		Run:          scripted(&calls, "abc\n", "", 0, nil),
	})
	if _, err := s.Read(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := []call{{
		name: "/opt/security",
		args: []string{"find-generic-password", "-a", "acct", "-s", "svc", "-w", kc},
	}}
	if !reflect.DeepEqual(calls, want) {
		t.Errorf("calls:\n got %+v\nwant %+v", calls, want)
	}
}

func TestWriteArgs(t *testing.T) {
	kc := tempKeychain(t)
	var calls []call
	s := New(Options{
		KeychainPath: kc,
		Service:      "svc",
		Account:      "acct",
		SecurityPath: "/opt/security",
		Run:          scripted(&calls, "", "", 0, nil),
	})
	if err := s.Write(context.Background(), []byte("dmFsdWU=")); err != nil {
		t.Fatal(err)
	}
	want := []call{{
		name: "/opt/security",
		args: []string{
			"add-generic-password", "-a", "acct", "-s", "svc",
			"-w", "dmFsdWU=", "-T", "/usr/bin/security", "-U", kc,
		},
	}}
	if !reflect.DeepEqual(calls, want) {
		t.Errorf("calls:\n got %+v\nwant %+v", calls, want)
	}
}

func TestReadValue(t *testing.T) {
	tests := []struct {
		name   string
		stdout string
		want   string
	}{
		{"strips one trailing newline", "abc\n", "abc"},
		{"strips only one newline", "abc\n\n", "abc\n"},
		{"no trailing newline", "abc", "abc"},
		{"embedded newline preserved", "a\nb\n", "a\nb"},
		{"empty output", "", ""},
		{"lone newline", "\n", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var calls []call
			s := New(Options{
				KeychainPath: tempKeychain(t),
				Run:          scripted(&calls, tc.stdout, "", 0, nil),
			})
			got, err := s.Read(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestReadErrors(t *testing.T) {
	tests := []struct {
		name       string
		stderr     string
		exitCode   int
		runErr     error
		wantNotFnd bool
		wantDetail string
	}{
		{
			name:       "exit 44 is not found",
			stderr:     "security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain.\n",
			exitCode:   44,
			wantNotFnd: true,
		},
		{
			name:       "could not be found in stderr is not found",
			stderr:     "security: The specified item could not be found in the keychain.\n",
			exitCode:   1,
			wantNotFnd: true,
		},
		{
			name:       "other exit is unavailable with first stderr line",
			stderr:     "security: SecKeychainUnlock: User interaction is not allowed.\nsecond line\n",
			exitCode:   36,
			wantDetail: "security: SecKeychainUnlock: User interaction is not allowed.",
		},
		{
			name:       "nonzero exit with empty stderr",
			exitCode:   51,
			wantDetail: "security exited 51",
		},
		{
			name:       "runner error is unavailable",
			runErr:     errors.New("fork/exec /usr/bin/security: no such file or directory"),
			exitCode:   -1,
			wantDetail: "fork/exec /usr/bin/security: no such file or directory",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var calls []call
			s := New(Options{
				KeychainPath: tempKeychain(t),
				Run:          scripted(&calls, "", tc.stderr, tc.exitCode, tc.runErr),
			})
			_, err := s.Read(context.Background())
			if tc.wantNotFnd {
				if !errors.Is(err, ErrNotFound) {
					t.Fatalf("got %v, want ErrNotFound", err)
				}
				return
			}
			var ue *UnavailableError
			if !errors.As(err, &ue) {
				t.Fatalf("got %T %v, want *UnavailableError", err, err)
			}
			if ue.Detail != tc.wantDetail {
				t.Errorf("detail: got %q, want %q", ue.Detail, tc.wantDetail)
			}
		})
	}
}

func TestReadMissingKeychainFile(t *testing.T) {
	var calls []call
	s := New(Options{
		KeychainPath: filepath.Join(t.TempDir(), "absent.keychain-db"),
		Run:          scripted(&calls, "", "", 0, nil),
	})
	_, err := s.Read(context.Background())
	var ue *UnavailableError
	if !errors.As(err, &ue) {
		t.Fatalf("got %T %v, want *UnavailableError", err, err)
	}
	if errors.Is(err, ErrNotFound) {
		t.Error("missing keychain file must not be ErrNotFound")
	}
	if !strings.Contains(ue.Detail, "absent.keychain-db") {
		t.Errorf("detail %q should name the keychain path", ue.Detail)
	}
	if len(calls) != 0 {
		t.Errorf("security should not run when the keychain file is missing, got %d calls", len(calls))
	}
}

func TestTimeout(t *testing.T) {
	// The runner blocks until the deadline the store applies, then reports
	// the kill the way exec does: exit -1 and the context error.
	blocking := func(ctx context.Context, _ string, _ ...string) ([]byte, []byte, int, error) {
		<-ctx.Done()
		return nil, nil, -1, ctx.Err()
	}
	s := New(Options{
		KeychainPath: tempKeychain(t),
		Timeout:      10 * time.Millisecond,
		Run:          blocking,
	})
	for name, op := range map[string]func(context.Context) error{
		"read": func(ctx context.Context) error {
			_, err := s.Read(ctx)
			return err
		},
		"write": func(ctx context.Context) error {
			return s.Write(ctx, []byte("x"))
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := op(context.Background())
			var ue *UnavailableError
			if !errors.As(err, &ue) {
				t.Fatalf("got %T %v, want *UnavailableError", err, err)
			}
			if !strings.Contains(ue.Detail, "timed out") {
				t.Errorf("detail %q should mention timeout", ue.Detail)
			}
		})
	}
}

func TestWriteErrors(t *testing.T) {
	secret := "c3VwZXJzZWNyZXQ="
	tests := []struct {
		name       string
		stderr     string
		exitCode   int
		runErr     error
		wantDetail string
	}{
		{
			name:       "nonzero exit never carries stderr",
			stderr:     "security: SecKeychainItemCreateFromContent: User interaction is not allowed.\n",
			exitCode:   36,
			wantDetail: "security add-generic-password exited 36",
		},
		{
			name:       "runner error never carries its text",
			runErr:     errors.New("boom"),
			exitCode:   -1,
			wantDetail: "security add-generic-password could not run",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var calls []call
			s := New(Options{
				KeychainPath: tempKeychain(t),
				Run:          scripted(&calls, "", tc.stderr, tc.exitCode, tc.runErr),
			})
			err := s.Write(context.Background(), []byte(secret))
			var ue *UnavailableError
			if !errors.As(err, &ue) {
				t.Fatalf("got %T %v, want *UnavailableError", err, err)
			}
			if ue.Detail != tc.wantDetail {
				t.Errorf("detail: got %q, want %q", ue.Detail, tc.wantDetail)
			}
			if strings.Contains(err.Error(), secret) {
				t.Error("error message leaks the value")
			}
		})
	}
}

// TestWriteErrorNeverEchoesValue models a security wrapper that prints its
// argv: the -w value shows up in stderr and in the runner error, and neither
// may reach the returned error.
func TestWriteErrorNeverEchoesValue(t *testing.T) {
	const secret = "c3VwZXJzZWNyZXQ="
	echoing := func(_ context.Context, name string, args ...string) ([]byte, []byte, int, error) {
		argv := name + " " + strings.Join(args, " ")
		return nil, []byte("wrapper: " + argv + "\n"), 1, errors.New("wrapper failed: " + argv)
	}
	for name, run := range map[string]Runner{
		"stderr and error": echoing,
		"stderr only": func(ctx context.Context, name string, args ...string) ([]byte, []byte, int, error) {
			_, stderr, code, _ := echoing(ctx, name, args...)
			return nil, stderr, code, nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			s := New(Options{KeychainPath: tempKeychain(t), Run: run})
			err := s.Write(context.Background(), []byte(secret))
			if err == nil {
				t.Fatal("want error")
			}
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("error leaks the value: %q", err.Error())
			}
			var ue *UnavailableError
			if !errors.As(err, &ue) || !strings.HasPrefix(ue.Detail, "security add-generic-password ") {
				t.Fatalf("got %T %v", err, err)
			}
		})
	}
}

func TestWriteTimeoutDetail(t *testing.T) {
	blocking := func(ctx context.Context, _ string, _ ...string) ([]byte, []byte, int, error) {
		<-ctx.Done()
		return nil, []byte("argv echo"), -1, ctx.Err()
	}
	s := New(Options{KeychainPath: tempKeychain(t), Timeout: 10 * time.Millisecond, Run: blocking})
	err := s.Write(context.Background(), []byte("x"))
	var ue *UnavailableError
	if !errors.As(err, &ue) {
		t.Fatalf("got %T %v", err, err)
	}
	if ue.Detail != "security add-generic-password timed out after 10ms" {
		t.Errorf("detail = %q", ue.Detail)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Error("write timeout does not unwrap to context.DeadlineExceeded")
	}
}

// TestExecRunnerClosesStdin runs a real subprocess that reads stdin; with
// stdin closed it must finish at once rather than wait on the terminal.
func TestExecRunnerClosesStdin(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stdout, _, code, err := execRunner(ctx, "/bin/sh", "-c", "cat; echo done")
	if err != nil || code != 0 {
		t.Fatalf("code=%d err=%v", code, err)
	}
	if string(stdout) != "done\n" {
		t.Errorf("stdout = %q", stdout)
	}
	if ctx.Err() != nil {
		t.Fatal("runner waited on stdin until the deadline")
	}
}

func TestWriteMissingKeychainFile(t *testing.T) {
	var calls []call
	s := New(Options{
		KeychainPath: filepath.Join(t.TempDir(), "absent.keychain-db"),
		Run:          scripted(&calls, "", "", 0, nil),
	})
	err := s.Write(context.Background(), []byte("x"))
	var ue *UnavailableError
	if !errors.As(err, &ue) {
		t.Fatalf("got %T %v, want *UnavailableError", err, err)
	}
	if len(calls) != 0 {
		t.Errorf("security should not run, got %d calls", len(calls))
	}
}

func TestUnavailableErrorMessage(t *testing.T) {
	err := &UnavailableError{Detail: "locked"}
	if got := err.Error(); got != "keychain unavailable: locked" {
		t.Errorf("got %q", got)
	}
	if got := (&UnavailableError{}).Error(); got != "keychain unavailable" {
		t.Errorf("got %q", got)
	}
}

func TestFake(t *testing.T) {
	ctx := context.Background()

	t.Run("read missing", func(t *testing.T) {
		f := &Fake{}
		if _, err := f.Read(ctx); !errors.Is(err, ErrNotFound) {
			t.Errorf("got %v, want ErrNotFound", err)
		}
	})

	t.Run("read existing", func(t *testing.T) {
		f := &Fake{Value: []byte("v"), Exists: true}
		got, err := f.Read(ctx)
		if err != nil || string(got) != "v" {
			t.Errorf("got %q, %v", got, err)
		}
	})

	t.Run("read error wins", func(t *testing.T) {
		want := &UnavailableError{Detail: "locked"}
		f := &Fake{Value: []byte("v"), Exists: true, ReadErr: want}
		if _, err := f.Read(ctx); !errors.Is(err, want) {
			t.Errorf("got %v, want %v", err, want)
		}
	})

	t.Run("write stores and counts", func(t *testing.T) {
		f := &Fake{}
		if err := f.Write(ctx, []byte("a")); err != nil {
			t.Fatal(err)
		}
		if err := f.Write(ctx, []byte("b")); err != nil {
			t.Fatal(err)
		}
		if !f.Exists || string(f.Value) != "b" || f.Writes != 2 {
			t.Errorf("state after writes: %+v", f)
		}
	})

	t.Run("write copies the slice", func(t *testing.T) {
		f := &Fake{}
		buf := []byte("abc")
		if err := f.Write(ctx, buf); err != nil {
			t.Fatal(err)
		}
		buf[0] = 'z'
		if string(f.Value) != "abc" {
			t.Errorf("fake aliased caller buffer: %q", f.Value)
		}
	})

	t.Run("write error leaves state", func(t *testing.T) {
		want := &UnavailableError{Detail: "locked"}
		f := &Fake{Value: []byte("old"), Exists: true, WriteErr: want}
		err := f.Write(ctx, []byte("new"))
		if !errors.Is(err, want) {
			t.Errorf("got %v, want %v", err, want)
		}
		if string(f.Value) != "old" || f.Writes != 0 {
			t.Errorf("state changed on failed write: %+v", f)
		}
	})
}

// Compile-time interface checks.
var (
	_ Store = (*store)(nil)
	_ Store = (*Fake)(nil)
)
