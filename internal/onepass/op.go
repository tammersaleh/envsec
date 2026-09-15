package onepass

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/tammersaleh/envsec/internal/export"
)

// Runner executes name with args and returns its output and exit code. err is
// non-nil only when the process could not run or was killed; a nonzero exit
// is reported through exitCode with err nil.
type Runner func(ctx context.Context, name string, args ...string) (stdout, stderr []byte, exitCode int, err error)

// Options configures the real client. Zero values are usable.
type Options struct {
	// Path is the `op` binary. Default "op" (resolved via PATH).
	Path string
	// Timeout bounds each `op` command. Default 60s, long enough for Touch ID.
	Timeout time.Duration
	// Verbose forwards raw `op` stderr to Stderr after `account list` and
	// `item list`. `item get` stderr is never forwarded: the item was fetched
	// with --reveal and op could echo a value.
	Verbose bool
	// Stderr receives forwarded `op` stderr when Verbose. Default os.Stderr.
	Stderr io.Writer
	// Runner runs the subprocess. Tests substitute canned output here.
	Runner Runner
}

// DefaultTimeout is the per-command timeout when Options.Timeout is zero.
const DefaultTimeout = 60 * time.Second

type client struct {
	opts Options
}

// New returns a Client that shells out to `op`.
func New(opts Options) Client {
	if opts.Path == "" {
		opts.Path = "op"
	}
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultTimeout
	}
	if opts.Stderr == nil {
		opts.Stderr = os.Stderr
	}
	if opts.Runner == nil {
		opts.Runner = execRunner
	}
	return &client{opts: opts}
}

func (c *client) Accounts(ctx context.Context) ([]Account, error) {
	out, err := c.run(ctx, Account{}, false, "account", "list", "--format", "json")
	if err != nil {
		return nil, err
	}
	var accounts []Account
	if err := decode(out, &accounts); err != nil {
		return nil, fmt.Errorf("op account list: %w", err)
	}
	type identity struct{ account, user string }
	seen := map[identity]bool{}
	for i, a := range accounts {
		if a.AccountUUID == "" || a.UserUUID == "" {
			return nil, fmt.Errorf("op account list: account %d has an empty account_uuid or user_uuid", i)
		}
		if a.URL == "" {
			return nil, fmt.Errorf("op account list: account %d has an empty url", i)
		}
		id := identity{a.AccountUUID, a.UserUUID}
		if seen[id] {
			return nil, fmt.Errorf("op account list: account %d repeats an earlier account_uuid and user_uuid", i)
		}
		seen[id] = true
	}
	if len(accounts) == 0 {
		return nil, &AuthError{Detail: "no 1Password accounts are signed in"}
	}
	return accounts, nil
}

func (c *client) ListTagged(ctx context.Context, account Account, tag string) ([]Item, error) {
	out, err := c.run(ctx, account, false, "item", "list", "--tags", tag, "--format", "json", "--account", account.AccountUUID)
	if err != nil {
		return nil, err
	}
	var items []Item
	if err := decode(out, &items); err != nil {
		return nil, fmt.Errorf("op item list: %w", err)
	}
	seen := map[string]bool{}
	for i := range items {
		if items[i].ID == "" {
			return nil, fmt.Errorf("op item list: item %d has an empty id", i)
		}
		if seen[items[i].ID] {
			return nil, fmt.Errorf("op item list: item %d has a duplicate id", i)
		}
		seen[items[i].ID] = true
		items[i].Fields = nil
	}
	if items == nil {
		items = []Item{}
	}
	return items, nil
}

func (c *client) GetItem(ctx context.Context, account Account, id string) (Item, error) {
	out, err := c.run(ctx, account, true, "item", "get", id, "--format", "json", "--reveal", "--account", account.AccountUUID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return Item{}, fmt.Errorf("%w: %s", ErrNotFound, id)
		}
		return Item{}, err
	}
	var w wireItem
	if err := decode(out, &w); err != nil {
		return Item{}, fmt.Errorf("op item get: %w", err)
	}
	if w.ID != id {
		return Item{}, fmt.Errorf("op item get: item id mismatch: asked for %s", id)
	}
	if w.Tags == nil {
		return Item{}, errors.New("op item get: item has no tags array")
	}
	if w.Fields == nil {
		return Item{}, errors.New("op item get: item has no fields array")
	}
	for i, f := range *w.Fields {
		if f.ID == "" {
			return Item{}, fmt.Errorf("op item get: field %d has an empty id", i)
		}
	}
	return Item{ID: w.ID, Title: w.Title, Vault: w.Vault, Tags: *w.Tags, Fields: *w.Fields}, nil
}

// wireItem is a full item before validation. Pointers tell a missing or null
// tags or fields apart from an explicit empty array, which is allowed.
type wireItem struct {
	ID     string    `json:"id"`
	Title  string    `json:"title"`
	Vault  Vault     `json:"vault"`
	Tags   *[]string `json:"tags"`
	Fields *[]Field  `json:"fields"`
}

// run executes one `op` command under the per-command timeout and classifies
// failures. account annotates AuthError. itemGet marks `item get`: its stderr
// is used for classification only and then discarded. It is never forwarded
// under Verbose and never reaches an error, because the item was fetched with
// --reveal; a not-found marker wins over auth markers, and every `item get`
// error carries fixed text. For `account list` and `item list` the first
// stderr line is the error detail and Verbose forwards stderr in full.
func (c *client) run(ctx context.Context, account Account, itemGet bool, args ...string) ([]byte, error) {
	cctx, cancel := context.WithTimeout(ctx, c.opts.Timeout)
	defer cancel()

	stdout, stderr, code, err := c.opts.Runner(cctx, c.opts.Path, args...)
	if c.opts.Verbose && !itemGet && len(stderr) > 0 {
		_, _ = c.opts.Stderr.Write(stderr)
	}
	if cctx.Err() != nil {
		// Parent cancellation is reported as-is; only our own deadline is a timeout.
		if ctx.Err() != nil {
			return nil, fmt.Errorf("op %v: %w", args, ctx.Err())
		}
		detail := fmt.Sprintf("op timed out after %s; a Touch ID or unlock prompt was probably unanswered", c.opts.Timeout)
		if !itemGet && isAuthFailure(stderr) {
			detail = firstLine(stderr)
		}
		return nil, &AuthError{Account: account, Detail: detail, Err: ErrTimeout}
	}
	if err != nil {
		if itemGet {
			return nil, errors.New("op item get could not run")
		}
		return nil, fmt.Errorf("op %v: %w", args, err)
	}
	if code != 0 {
		if itemGet {
			switch {
			case isNotFound(stderr):
				return nil, ErrNotFound
			case isAuthFailure(stderr):
				return nil, &AuthError{Account: account, Detail: fmt.Sprintf("op item get exited %d with an authorization error", code)}
			}
			return nil, &CommandError{Args: args, ExitCode: code, Detail: fmt.Sprintf("op item get exited %d", code)}
		}
		if isAuthFailure(stderr) {
			return nil, &AuthError{Account: account, Detail: firstLine(stderr)}
		}
		return nil, &CommandError{Args: args, ExitCode: code, Detail: firstLine(stderr)}
	}
	return stdout, nil
}

// decode unmarshals out into v. Only real JSON counts: empty, whitespace, a
// bare null, or invalid UTF-8 is malformed output, never an empty result.
func decode(out []byte, v any) error {
	out = bytes.TrimSpace(out)
	if len(out) == 0 || bytes.Equal(out, []byte("null")) {
		return errors.New("malformed output: expected a JSON document")
	}
	if !utf8.Valid(out) {
		return errors.New("malformed output: invalid UTF-8")
	}
	return json.Unmarshal(out, v)
}

// authPatterns are the stderr markers, matched case-insensitively as
// substrings, that mean `op` could not authorize.
var authPatterns = []string{
	"not signed in",
	"not currently signed in",
	"session expired",
	"authorization",
	"authentication required",
	"unlock",
	"locked",
	"touch id",
	"no accounts configured",
}

func isAuthFailure(stderr []byte) bool {
	s := strings.ToLower(string(stderr))
	for _, p := range authPatterns {
		if strings.Contains(s, p) {
			return true
		}
	}
	return false
}

func isNotFound(stderr []byte) bool {
	s := strings.ToLower(string(stderr))
	return strings.Contains(s, "isn't an item") || strings.Contains(s, "not found")
}

func firstLine(b []byte) string {
	s := strings.TrimSpace(string(b))
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

// execRunner is the default Runner: a real subprocess with stdin closed so a
// prompting `op` cannot wait on a TTY. The context kills the process; WaitDelay
// bounds the wait for pipes held open by any child `op` leaves behind. The
// child's environment is scrubbed of the vars envsec itself exported.
func execRunner(ctx context.Context, name string, args ...string) ([]byte, []byte, int, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = nil
	cmd.WaitDelay = 2 * time.Second
	cmd.Env = scrubEnv(os.Environ())
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err == nil {
		return stdout.Bytes(), stderr.Bytes(), 0, nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) && ctx.Err() == nil {
		return stdout.Bytes(), stderr.Bytes(), ee.ExitCode(), nil
	}
	return stdout.Bytes(), stderr.Bytes(), -1, err
}

// managedVar is the sentinel `envsec env` exports listing the names it set.
const managedVar = "ENVSEC_MANAGED_VARS"

// scrubEnv returns environ without managedVar and without every name it
// lists that envsec could have exported (matches export.LabelPattern and is
// not denylisted), so the secrets a shell loaded from the keychain never reach
// the `op` child. Other listed names are ignored rather than trusted: a
// tampered sentinel must not strip PATH or HOME from the child.
func scrubEnv(environ []string) []string {
	drop := map[string]bool{managedVar: true}
	for _, kv := range environ {
		if k, v, ok := strings.Cut(kv, "="); ok && k == managedVar {
			for _, name := range strings.Fields(v) {
				if export.LabelPattern.MatchString(name) && !export.Denied(name) {
					drop[name] = true
				}
			}
		}
	}
	out := make([]string, 0, len(environ))
	for _, kv := range environ {
		k, _, _ := strings.Cut(kv, "=")
		if !drop[k] {
			out = append(out, kv)
		}
	}
	return out
}
