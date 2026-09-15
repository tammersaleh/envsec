// Package keychain stores one opaque value in the macOS login keychain.
//
// All access goes through /usr/bin/security, never Security.framework; see
// docs/plan.md "Design decision". The package neither encodes nor decodes the
// value; it returns the bytes exactly as security prints them, minus the
// trailing newline security adds.
package keychain

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Store reads and replaces the single keychain item envsec owns.
type Store interface {
	// Read returns the item's value, raw bytes as stored. It returns
	// ErrNotFound when the item does not exist and *UnavailableError when the
	// keychain cannot be used.
	Read(ctx context.Context) ([]byte, error)
	// Write replaces the item's value atomically, creating it if absent.
	Write(ctx context.Context, value []byte) error
}

// ErrNotFound reports that the keychain is usable but holds no item.
var ErrNotFound = errors.New("keychain item not found")

// UnavailableError reports that the keychain could not be used: locked,
// missing file, security failure, or timeout. Callers map it to exit code 4.
// Detail is the first line of security's stderr or a short description; it
// never contains the item value.
type UnavailableError struct {
	Detail string
	err    error
}

func (e *UnavailableError) Error() string {
	if e.Detail == "" {
		return "keychain unavailable"
	}
	return "keychain unavailable: " + e.Detail
}

// Unwrap exposes the cause (context.DeadlineExceeded on timeout) for
// errors.Is; the cause never appears in Error.
func (e *UnavailableError) Unwrap() error { return e.err }

// Runner executes name with args and returns its output, exit code, and any
// error starting or waiting on the process. On a context deadline exec reports
// exitCode -1 and err carrying the context error.
type Runner func(ctx context.Context, name string, args ...string) (stdout, stderr []byte, exitCode int, err error)

// Options configures the real Store. Zero values take the defaults below.
type Options struct {
	// KeychainPath is passed to every security call. Default
	// $HOME/Library/Keychains/login.keychain-db.
	KeychainPath string
	// Service is the item's -s. Default "envsec".
	Service string
	// Account is the item's -a. Default "bundle".
	Account string
	// SecurityPath is the binary to run. Default /usr/bin/security.
	SecurityPath string
	// Timeout bounds each security call. Default 10s.
	Timeout time.Duration
	// Run executes security. Default uses os/exec. Tests inject a fake.
	Run Runner
}

const (
	defaultService  = "envsec"
	defaultAccount  = "bundle"
	defaultSecurity = "/usr/bin/security"
	defaultTimeout  = 10 * time.Second

	// exitNotFound is errSecItemNotFound as reported by security.
	exitNotFound = 44
)

type store struct {
	opts Options
}

// New returns a Store backed by /usr/bin/security.
func New(opts Options) Store {
	if opts.KeychainPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			home = os.Getenv("HOME")
		}
		opts.KeychainPath = filepath.Join(home, "Library", "Keychains", "login.keychain-db")
	}
	if opts.Service == "" {
		opts.Service = defaultService
	}
	if opts.Account == "" {
		opts.Account = defaultAccount
	}
	if opts.SecurityPath == "" {
		opts.SecurityPath = defaultSecurity
	}
	if opts.Timeout <= 0 {
		opts.Timeout = defaultTimeout
	}
	if opts.Run == nil {
		opts.Run = execRunner
	}
	return &store{opts: opts}
}

func (s *store) Read(ctx context.Context) ([]byte, error) {
	if err := s.checkKeychainFile(); err != nil {
		return nil, err
	}
	stdout, stderr, code, err := s.run(ctx,
		"find-generic-password",
		"-a", s.opts.Account,
		"-s", s.opts.Service,
		"-w",
		s.opts.KeychainPath,
	)
	if err != nil {
		// find-generic-password has no value in argv, so the runner's own text
		// is safe to show.
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, &UnavailableError{Detail: fmt.Sprintf("security timed out after %s", s.opts.Timeout), err: err}
		}
		return nil, &UnavailableError{Detail: err.Error(), err: err}
	}
	if code == exitNotFound || bytes.Contains(stderr, []byte("could not be found")) {
		return nil, ErrNotFound
	}
	if code != 0 {
		return nil, unavailable(stderr, code)
	}
	// -w prints the value followed by exactly one newline.
	return bytes.TrimSuffix(stdout, []byte("\n")), nil
}

func (s *store) Write(ctx context.Context, value []byte) error {
	if err := s.checkKeychainFile(); err != nil {
		return err
	}
	// The value lands in argv for the lifetime of the security process. This is
	// the one accepted exposure; see CLAUDE.md "Design constraints". Because a
	// wrapper around security could echo that argv, no failure here carries
	// stderr or the runner error: only the exit code or a fixed phrase.
	const what = "security add-generic-password"
	_, _, code, err := s.run(ctx,
		"add-generic-password",
		"-a", s.opts.Account,
		"-s", s.opts.Service,
		"-w", string(value),
		"-T", defaultSecurity,
		"-U",
		s.opts.KeychainPath,
	)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return &UnavailableError{Detail: fmt.Sprintf("%s timed out after %s", what, s.opts.Timeout), err: err}
		}
		return &UnavailableError{Detail: what + " could not run"}
	}
	if code != 0 {
		return &UnavailableError{Detail: fmt.Sprintf("%s exited %d", what, code)}
	}
	return nil
}

// checkKeychainFile distinguishes a missing keychain from a missing item:
// security exits 44 for both.
func (s *store) checkKeychainFile() error {
	if _, err := os.Stat(s.opts.KeychainPath); err != nil {
		return &UnavailableError{Detail: fmt.Sprintf("keychain %s: %v", s.opts.KeychainPath, errString(err))}
	}
	return nil
}

// run invokes security under the configured timeout. A non-nil error means the
// process could not be run to completion: the context error (which is
// context.DeadlineExceeded on timeout) or the runner's own error, raw. The
// caller classifies it and decides what text is safe to show, because on the
// Write path argv holds the value. A nonzero code means it ran and failed.
func (s *store) run(ctx context.Context, args ...string) (stdout, stderr []byte, code int, err error) {
	ctx, cancel := context.WithTimeout(ctx, s.opts.Timeout)
	defer cancel()

	stdout, stderr, code, err = s.opts.Run(ctx, s.opts.SecurityPath, args...)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, nil, code, ctxErr
	}
	if err != nil {
		return nil, nil, code, err
	}
	return stdout, stderr, code, nil
}

// unavailable builds the error for a nonzero security exit.
func unavailable(stderr []byte, code int) error {
	line, _, _ := strings.Cut(strings.TrimSpace(string(stderr)), "\n")
	if line == "" {
		line = fmt.Sprintf("security exited %d", code)
	}
	return &UnavailableError{Detail: line}
}

// errString strips the *PathError prefix so the detail names the path once.
func errString(err error) string {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}
	return err.Error()
}

// execRunner is the default Runner. Stdin is closed so a prompting security
// cannot wait on a TTY; WaitDelay bounds the wait for pipes a killed process
// leaves open.
func execRunner(ctx context.Context, name string, args ...string) ([]byte, []byte, int, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = nil
	cmd.WaitDelay = 2 * time.Second
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			// The process ran and exited nonzero (or was killed: -1). Not a
			// runner failure; the caller reads the code.
			return stdout.Bytes(), stderr.Bytes(), ee.ExitCode(), nil
		}
		return stdout.Bytes(), stderr.Bytes(), -1, err
	}
	return stdout.Bytes(), stderr.Bytes(), code, nil
}
