package cli

// SyncCmd copies tagged 1Password fields into the keychain bundle. Stub: phase
// 3 replaces it.
type SyncCmd struct{}

func (SyncCmd) Run(*runContext) error {
	return &ExitError{Code: ExitFailure, Err: "not_implemented", Detail: "sync is not implemented yet"}
}
