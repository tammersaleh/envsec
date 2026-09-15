package cli

// CheckCmd compares 1Password against the keychain bundle. Stub: phase 3
// replaces it.
type CheckCmd struct{}

func (CheckCmd) Run(*runContext) error {
	return &ExitError{Code: ExitFailure, Err: "not_implemented", Detail: "check is not implemented yet"}
}
