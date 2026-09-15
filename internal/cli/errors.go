package cli

import (
	"encoding/json"
	"errors"
	"io"

	"github.com/tammersaleh/envsec/internal/bundle"
	"github.com/tammersaleh/envsec/internal/keychain"
	"github.com/tammersaleh/envsec/internal/onepass"
)

// Exit codes. See SPEC.md "Output and errors".
const (
	ExitOK          = 0
	ExitFailure     = 1
	ExitOnePassAuth = 2
	ExitKeychain    = 4
)

// ExitError is a fatal command failure. Err is the stable snake_case code
// printed as `error`; Detail and Hint fill the other two fields of the JSON
// object on stderr. Silent means the command already wrote its own stderr
// line (env does this) and the JSON object must not be printed.
type ExitError struct {
	Code   int
	Err    string
	Detail string
	Hint   string
	Silent bool
}

func (e *ExitError) Error() string {
	if e.Detail == "" {
		return e.Err
	}
	return e.Err + ": " + e.Detail
}

// ExitCode maps the error returned by Run to a process exit status.
func ExitCode(err error) int {
	if err == nil {
		return ExitOK
	}
	var ee *ExitError
	if errors.As(err, &ee) {
		return ee.Code
	}
	return ExitFailure
}

const hintSync = "envsec sync"

// asExit converts any error into an *ExitError using the SPEC mapping. An
// error that already is one passes through.
func asExit(err error) *ExitError {
	var ee *ExitError
	if errors.As(err, &ee) {
		return ee
	}
	var ae *onepass.AuthError
	if errors.As(err, &ae) {
		hint := "op signin"
		if ae.Account.URL != "" {
			hint = "op signin --account " + ae.Account.URL
		}
		return &ExitError{Code: ExitOnePassAuth, Err: "onepassword_unauthorized", Detail: ae.Detail, Hint: hint}
	}
	var ue *keychain.UnavailableError
	if errors.As(err, &ue) {
		return &ExitError{Code: ExitKeychain, Err: "keychain_unavailable", Detail: ue.Error(), Hint: hintSync}
	}
	if errors.Is(err, keychain.ErrNotFound) {
		return &ExitError{Code: ExitKeychain, Err: "bundle_missing", Detail: "no envsec bundle in the keychain", Hint: hintSync}
	}
	if errors.Is(err, bundle.ErrBadBase64) || errors.Is(err, bundle.ErrBadJSON) || errors.Is(err, bundle.ErrUnknownSchema) {
		return &ExitError{Code: ExitKeychain, Err: "bundle_invalid", Detail: err.Error(), Hint: hintSync}
	}
	return &ExitError{Code: ExitFailure, Err: "failed", Detail: err.Error()}
}

// fatalJSON is the wire shape of a fatal error on stderr.
type fatalJSON struct {
	Error  string `json:"error"`
	Detail string `json:"detail"`
	Hint   string `json:"hint"`
}

// writeFatal prints the single JSON object for a fatal error.
func writeFatal(w io.Writer, e *ExitError) {
	raw, err := json.Marshal(fatalJSON{Error: e.Err, Detail: e.Detail, Hint: e.Hint})
	if err != nil {
		return
	}
	_, _ = w.Write(append(raw, '\n'))
}
