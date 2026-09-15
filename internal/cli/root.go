package cli

import (
	"fmt"
	"io"
)

// Run is the CLI entry point. Commands are added as the SPEC lands; until then
// only `version` exists so the build, lint, and release pipeline can be proven.
func Run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 1 && args[0] == "version" {
		if _, err := fmt.Fprintf(stdout, "{\"version\":%q}\n", Version); err != nil {
			return err
		}
		_, err := fmt.Fprintln(stdout, `{"_meta":{"has_more":false}}`)
		return err
	}
	return fmt.Errorf("envsec: not implemented yet; see SPEC.md")
}
