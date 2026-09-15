// Command envsec exports 1Password secrets as environment variables via the
// macOS login keychain. See SPEC.md.
package main

import (
	"os"

	"github.com/tammersaleh/envsec/internal/cli"
)

func main() {
	os.Exit(cli.ExitCode(cli.Run(os.Args[1:], os.Stdout, os.Stderr)))
}
