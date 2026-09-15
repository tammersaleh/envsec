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
	// Verbose forwards raw `op` stderr to Stderr after every command.
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
	out, err := c.run(ctx, Account{}, "account", "list", "--format", "json")
	if err != nil {
		return nil, err
	}
	accounts := []Account{}
	if err := decode(out, &accounts); err != nil {
		return nil, fmt.Errorf("op account list: %w", err)
	}
	return accounts, nil
}

func (c *client) ListTagged(ctx context.Context, account Account, tag string) ([]Item, error) {
	out, err := c.run(ctx, account, "item", "list", "--tags", tag, "--format", "json", "--account", account.AccountUUID)
	if err != nil {
		return nil, err
	}
	items := []Item{}
	if err := decode(out, &items); err != nil {
		return nil, fmt.Errorf("op item list: %w", err)
	}
	for i := range items {
		items[i].Fields = nil
	}
	return items, nil
}

func (c *client) GetItem(ctx context.Context, account Account, id string) (Item, error) {
	out, err := c.run(ctx, account, "item", "get", id, "--format", "json", "--reveal", "--account", account.AccountUUID)
	if err != nil {
		var ce *CommandError
		if errors.As(err, &ce) && isNotFound(ce.Detail) {
			return Item{}, fmt.Errorf("%w: %s", ErrNotFound, ce.Detail)
		}
		return Item{}, err
	}
	var item Item
	if err := decode(out, &item); err != nil {
		return Item{}, fmt.Errorf("op item get: %w", err)
	}
	return item, nil
}

// run executes one `op` command under the per-command timeout and classifies
// failures. account is only used to annotate AuthError.
func (c *client) run(ctx context.Context, account Account, args ...string) ([]byte, error) {
	cctx, cancel := context.WithTimeout(ctx, c.opts.Timeout)
	defer cancel()

	stdout, stderr, code, err := c.opts.Runner(cctx, c.opts.Path, args...)
	if c.opts.Verbose && len(stderr) > 0 {
		_, _ = c.opts.Stderr.Write(stderr)
	}
	if cctx.Err() != nil {
		// Parent cancellation is reported as-is; only our own deadline is a timeout.
		if ctx.Err() != nil {
			return nil, fmt.Errorf("op %v: %w", args, ctx.Err())
		}
		return nil, fmt.Errorf("%w after %s: op %v", ErrTimeout, c.opts.Timeout, args)
	}
	if err != nil {
		return nil, fmt.Errorf("op %v: %w", args, err)
	}
	if code != 0 {
		detail := firstLine(stderr)
		if isAuthFailure(stderr) {
			return nil, &AuthError{Account: account, Detail: detail}
		}
		return nil, &CommandError{Args: args, ExitCode: code, Detail: detail}
	}
	return stdout, nil
}

// decode unmarshals out into v. Empty or whitespace-only output leaves v
// untouched, so callers pre-seed slices with an empty value.
func decode(out []byte, v any) error {
	out = bytes.TrimSpace(out)
	if len(out) == 0 {
		return nil
	}
	return json.Unmarshal(out, v)
}

var authPatterns = []string{
	"not signed in",
	"not currently signed in",
	"authorization",
	"session expired",
	"touch id",
	"unlock",
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

func isNotFound(detail string) bool {
	s := strings.ToLower(detail)
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
// bounds the wait for pipes held open by any child `op` leaves behind.
func execRunner(ctx context.Context, name string, args ...string) ([]byte, []byte, int, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = nil
	cmd.WaitDelay = 2 * time.Second
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
