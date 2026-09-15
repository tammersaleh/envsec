package onepass

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func newFake() *Fake {
	return &Fake{
		AccountList: []Account{acct1, acct2},
		Items: map[string][]Item{
			acct1.AccountUUID: {
				{ID: "i1", Title: "one", Tags: []string{"shell-env"}, Fields: []Field{{ID: "f", Type: "CONCEALED", Label: "A", Value: "v"}}},
				{ID: "i2", Title: "two", Tags: []string{"other"}, Fields: []Field{{ID: "f", Type: "CONCEALED", Label: "B", Value: "v"}}},
			},
			acct2.AccountUUID: {
				{ID: "i3", Title: "three", Tags: []string{"shell-env", "x"}, Fields: []Field{{ID: "f", Type: "CONCEALED", Label: "C", Value: "v"}}},
			},
		},
	}
}

func TestFakeImplementsClient(t *testing.T) {
	var _ Client = (*Fake)(nil)
}

func TestFakeAccounts(t *testing.T) {
	f := newFake()
	got, err := f.Accounts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, []Account{acct1, acct2}) {
		t.Errorf("got %+v", got)
	}
	got[0].URL = "mutated"
	if f.AccountList[0].URL == "mutated" {
		t.Error("Accounts returned aliased slice")
	}
}

func TestFakeListTaggedFiltersAndStrips(t *testing.T) {
	f := newFake()
	got, err := f.ListTagged(context.Background(), acct1, "shell-env")
	if err != nil {
		t.Fatal(err)
	}
	want := []Item{{ID: "i1", Title: "one", Tags: []string{"shell-env"}}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}

	got, err = f.ListTagged(context.Background(), acct2, "nope")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || len(got) != 0 {
		t.Errorf("no match: got %#v, want empty non-nil", got)
	}

	got, err = f.ListTagged(context.Background(), Account{AccountUUID: "unknown"}, "shell-env")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || len(got) != 0 {
		t.Errorf("unknown account: got %#v, want empty non-nil", got)
	}
}

func TestFakeGetItem(t *testing.T) {
	f := newFake()
	got, err := f.GetItem(context.Background(), acct2, "i3")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, f.Items[acct2.AccountUUID][0]) {
		t.Errorf("got %+v", got)
	}
	got.Fields[0].Value = "mutated"
	got.Tags[0] = "mutated"
	if f.Items[acct2.AccountUUID][0].Fields[0].Value == "mutated" || f.Items[acct2.AccountUUID][0].Tags[0] == "mutated" {
		t.Error("GetItem returned aliased slices")
	}

	// Item exists in another account only.
	if _, err := f.GetItem(context.Background(), acct1, "i3"); !errors.Is(err, ErrNotFound) {
		t.Errorf("cross-account: err = %v, want ErrNotFound", err)
	}
	if _, err := f.GetItem(context.Background(), acct1, "missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing: err = %v, want ErrNotFound", err)
	}
}

func TestFakeErrs(t *testing.T) {
	f := newFake()
	boom := errors.New("boom")
	auth := &AuthError{Account: acct1, Detail: "locked"}
	f.Errs = FakeErrs{Accounts: boom, ListTagged: auth, GetItem: boom}

	if _, err := f.Accounts(context.Background()); !errors.Is(err, boom) {
		t.Errorf("Accounts err = %v", err)
	}
	_, err := f.ListTagged(context.Background(), acct1, "shell-env")
	var ae *AuthError
	if !errors.As(err, &ae) {
		t.Errorf("ListTagged err = %v", err)
	}
	if _, err := f.GetItem(context.Background(), acct1, "i1"); !errors.Is(err, boom) {
		t.Errorf("GetItem err = %v", err)
	}
}

func TestFakeCallLog(t *testing.T) {
	f := newFake()
	ctx := context.Background()
	f.Accounts(ctx)
	f.ListTagged(ctx, acct1, "shell-env")
	f.GetItem(ctx, acct1, "i1")
	want := []Call{
		{Method: "Accounts"},
		{Method: "ListTagged", AccountUUID: acct1.AccountUUID, Arg: "shell-env"},
		{Method: "GetItem", AccountUUID: acct1.AccountUUID, Arg: "i1"},
	}
	if !reflect.DeepEqual(f.Calls, want) {
		t.Errorf("calls = %+v, want %+v", f.Calls, want)
	}
}
