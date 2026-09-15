// Package cli is the Kong command layer: global flags, the commands, and the
// output and exit-code contract from SPEC.md "Output and errors".
package cli

import (
	"context"
	"io"
	"os"
	"time"

	"github.com/alecthomas/kong"

	"github.com/tammersaleh/envsec/internal/bundle"
	"github.com/tammersaleh/envsec/internal/keychain"
	"github.com/tammersaleh/envsec/internal/onepass"
)

// Globals are the flags every command accepts. See SPEC.md "Global flags".
type Globals struct {
	Tag      string        `help:"1Password tag that opts an item in." default:"shell-env"`
	Keychain string        `help:"Keychain file to use instead of the login keychain." type:"path" placeholder:"PATH"`
	Timeout  time.Duration `help:"Per external command. Default 60s for op, 10s for security."`
	Verbose  bool          `short:"v" help:"Log external commands to stderr."`
}

// CLI is the Kong grammar.
type CLI struct {
	Globals

	Version VersionCmd `cmd:"" help:"Print the build version."`
	Env     EnvCmd     `cmd:"" help:"Print export lines from the keychain bundle for eval."`
	List    ListCmd    `cmd:"" help:"Print the bundle's provenance, no values."`
	Sync    SyncCmd    `cmd:"" help:"Copy tagged 1Password fields into the keychain bundle."`
	Check   CheckCmd   `cmd:"" help:"Compare 1Password against the keychain bundle."`
}

// Deps are the external dependencies a command may use. Tests supply fakes;
// Run builds the real ones from Globals.
type Deps struct {
	Keychain keychain.Store
	OnePass  onepass.Client
	Now      func() time.Time
	Env      func(string) string
}

// DepsBuilder constructs Deps once the global flags are known.
type DepsBuilder func(Globals, io.Writer) Deps

// newKeychain and newOnePass are the real constructors. Tests replace them to
// observe the options Run derives from flags.
var (
	newKeychain = keychain.New
	newOnePass  = onepass.New
)

// RealDeps is the DepsBuilder Run uses.
func RealDeps(g Globals, stderr io.Writer) Deps {
	return Deps{
		Keychain: newKeychain(keychain.Options{KeychainPath: g.Keychain, Timeout: g.Timeout}),
		OnePass:  newOnePass(onepass.Options{Timeout: g.Timeout, Verbose: g.Verbose, Stderr: stderr}),
		Now:      time.Now,
		Env:      os.Getenv,
	}
}

// runContext is bound into every command's Run method.
type runContext struct {
	ctx     context.Context
	globals Globals
	deps    Deps
	stdout  io.Writer
	stderr  io.Writer
}

// Run is the CLI entry point with real dependencies. The returned error, if
// any, has already been reported on stderr; main maps it with ExitCode.
func Run(args []string, stdout, stderr io.Writer) error {
	return run(args, stdout, stderr, RealDeps)
}

// RunWith is Run with injected dependencies, for tests. Fields left nil in
// deps fall back to the real ones.
func RunWith(args []string, stdout, stderr io.Writer, deps Deps) error {
	return run(args, stdout, stderr, func(g Globals, w io.Writer) Deps {
		real := RealDeps(g, w)
		if deps.Keychain == nil {
			deps.Keychain = real.Keychain
		}
		if deps.OnePass == nil {
			deps.OnePass = real.OnePass
		}
		if deps.Now == nil {
			deps.Now = real.Now
		}
		if deps.Env == nil {
			deps.Env = real.Env
		}
		return deps
	})
}

func run(args []string, stdout, stderr io.Writer, build DepsBuilder) error {
	var cli CLI
	var exited *int
	parser, err := kong.New(&cli,
		kong.Name("envsec"),
		kong.Description("Export 1Password secrets as environment variables through the macOS login keychain."),
		kong.Writers(stderr, stderr),
		kong.Exit(func(code int) { exited = &code }),
		kong.ConfigureHelp(kong.HelpOptions{Compact: true}),
	)
	if err != nil {
		return report(stderr, err)
	}
	kctx, err := parser.Parse(args)
	if exited != nil {
		// --help or similar: Kong printed and asked to exit.
		if *exited == 0 {
			return nil
		}
		return &ExitError{Code: *exited, Err: "usage", Silent: true}
	}
	if err != nil {
		return report(stderr, &ExitError{Code: ExitFailure, Err: "usage", Detail: err.Error(), Hint: "envsec --help"})
	}
	rc := &runContext{
		ctx:     context.Background(),
		globals: cli.Globals,
		deps:    build(cli.Globals, stderr),
		stdout:  stdout,
		stderr:  stderr,
	}
	if err := kctx.Run(rc); err != nil {
		return report(stderr, err)
	}
	return nil
}

// report prints the fatal JSON object unless the command already spoke, and
// returns the normalized *ExitError.
func report(stderr io.Writer, err error) error {
	e := asExit(err)
	if !e.Silent {
		writeFatal(stderr, e)
	}
	return e
}

// readBundle reads and decodes the keychain bundle, mapping every failure to
// an exit-4 *ExitError.
func readBundle(rc *runContext) (bundle.Bundle, error) {
	raw, err := rc.deps.Keychain.Read(rc.ctx)
	if err != nil {
		return bundle.Bundle{}, asExit(err)
	}
	b, err := bundle.Decode(raw)
	if err != nil {
		return bundle.Bundle{}, &ExitError{Code: ExitKeychain, Err: "bundle_invalid", Detail: err.Error(), Hint: hintSync}
	}
	return b, nil
}
