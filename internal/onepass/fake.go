package onepass

import (
	"context"
	"fmt"
	"slices"
)

// Fake is an in-memory Client for tests in this package and internal/cli.
//
// Populate AccountList and Items (full items, keyed by account UUID). ListTagged
// filters Items by HasTag and returns copies with Fields stripped; GetItem
// returns a copy of the full item or ErrNotFound. Set Errs to make a method
// fail. Every call is appended to Calls.
type Fake struct {
	AccountList []Account
	Items       map[string][]Item
	Errs        FakeErrs
	Calls       []Call
}

// FakeErrs holds one error per Client method. A non-nil entry is returned by
// that method before it does anything else.
type FakeErrs struct {
	Accounts   error
	ListTagged error
	GetItem    error
}

// Call is one recorded Fake invocation. Arg is the tag for ListTagged and the
// item ID for GetItem.
type Call struct {
	Method      string
	AccountUUID string
	Arg         string
}

var _ Client = (*Fake)(nil)

func (f *Fake) Accounts(_ context.Context) ([]Account, error) {
	f.Calls = append(f.Calls, Call{Method: "Accounts"})
	if f.Errs.Accounts != nil {
		return nil, f.Errs.Accounts
	}
	return slices.Clone(f.AccountList), nil
}

func (f *Fake) ListTagged(_ context.Context, account Account, tag string) ([]Item, error) {
	f.Calls = append(f.Calls, Call{Method: "ListTagged", AccountUUID: account.AccountUUID, Arg: tag})
	if f.Errs.ListTagged != nil {
		return nil, f.Errs.ListTagged
	}
	out := []Item{}
	for _, it := range f.Items[account.AccountUUID] {
		if !HasTag(it, tag) {
			continue
		}
		summary := cloneItem(it)
		summary.Fields = nil
		out = append(out, summary)
	}
	return out, nil
}

func (f *Fake) GetItem(_ context.Context, account Account, id string) (Item, error) {
	f.Calls = append(f.Calls, Call{Method: "GetItem", AccountUUID: account.AccountUUID, Arg: id})
	if f.Errs.GetItem != nil {
		return Item{}, f.Errs.GetItem
	}
	for _, it := range f.Items[account.AccountUUID] {
		if it.ID == id {
			return cloneItem(it), nil
		}
	}
	return Item{}, fmt.Errorf("%w: %s in %s", ErrNotFound, id, account.AccountUUID)
}

// cloneItem deep-copies the slices so callers cannot mutate Fake state.
func cloneItem(it Item) Item {
	it.Tags = slices.Clone(it.Tags)
	it.Fields = slices.Clone(it.Fields)
	return it
}
