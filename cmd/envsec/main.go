// Command envsec exports 1Password secrets as environment variables via the
// macOS login keychain. See SPEC.md.
package main

import (
	"fmt"
	"os"

	"github.com/tammersaleh/envsec/internal/cli"
)

func main() {
	if err := cli.Run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
