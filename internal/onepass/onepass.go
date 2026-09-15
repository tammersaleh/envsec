// Package onepass wraps the 1Password CLI (`op`). Client is the interface the
// commands depend on; New returns the real implementation and Fake is the
// in-memory test double.
//
// Every `op` invocation is a fresh CLI session and may raise a Touch ID
// prompt, so every method takes a context and the real client applies a
// per-command timeout. Nothing here logs secret values.
package onepass

import (
	"context"
	"errors"
	"fmt"
)

// Account is one row of `op account list`.
type Account struct {
	URL         string `json:"url"`
	Email       string `json:"email"`
	UserUUID    string `json:"user_uuid"`
	AccountUUID string `json:"account_uuid"`
}

// Field is one entry of an item's `fields` array. Value is empty for fields
// that have none (notes, unset fields) and for summaries from ListTagged.
type Field struct {
	ID    string `json:"id"`
	Type  string `json:"type"`
	Label string `json:"label"`
	Value string `json:"value"`
}

// Vault identifies the vault an item lives in.
type Vault struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Item is a 1Password item. ListTagged returns summaries with Fields nil;
// GetItem returns the full item.
type Item struct {
	ID     string   `json:"id"`
	Title  string   `json:"title"`
	Vault  Vault    `json:"vault"`
	Tags   []string `json:"tags"`
	Fields []Field  `json:"fields"`
}

// Client is what the commands use to talk to 1Password.
type Client interface {
	// Accounts lists every account `op` is signed in to or knows about.
	Accounts(ctx context.Context) ([]Account, error)
	// ListTagged returns summaries (Fields nil) of items in the account
	// carrying tag. Zero matches is an empty slice, not an error.
	ListTagged(ctx context.Context, account Account, tag string) ([]Item, error)
	// GetItem fetches one item by ID, with revealed field values.
	GetItem(ctx context.Context, account Account, id string) (Item, error)
}

// HasTag reports whether item carries tag exactly (case-sensitive).
func HasTag(item Item, tag string) bool {
	for _, t := range item.Tags {
		if t == tag {
			return true
		}
	}
	return false
}

var (
	// ErrTimeout is returned when a single `op` command exceeds Options.Timeout.
	ErrTimeout = errors.New("op: command timed out")
	// ErrNotFound is returned by GetItem when `op` reports no such item.
	ErrNotFound = errors.New("op: item not found")
)

// AuthError means `op` could not authorize: locked, signed out, or a dismissed
// Touch ID prompt. Callers map it to exit code 2. Account is the zero value
// when the failing command was not account-scoped.
type AuthError struct {
	Account Account
	Detail  string
}

func (e *AuthError) Error() string {
	if e.Account.URL == "" {
		return "op: not authorized: " + e.Detail
	}
	return fmt.Sprintf("op: not authorized for %s: %s", e.Account.URL, e.Detail)
}

// CommandError is any other nonzero exit from `op`. Detail is the first line
// of stderr.
type CommandError struct {
	Args     []string
	ExitCode int
	Detail   string
}

func (e *CommandError) Error() string {
	if e.Detail == "" {
		return fmt.Sprintf("op %v: exit %d", e.Args, e.ExitCode)
	}
	return fmt.Sprintf("op %v: exit %d: %s", e.Args, e.ExitCode, e.Detail)
}
