package keychain

import "context"

// Fake is an in-memory Store for tests in other packages.
//
// Read returns ReadErr if set, ErrNotFound if !Exists, else Value. Write
// returns WriteErr if set, otherwise stores a copy of value, sets Exists, and
// increments Writes.
type Fake struct {
	Value    []byte
	Exists   bool
	ReadErr  error
	WriteErr error
	Writes   int
}

func (f *Fake) Read(context.Context) ([]byte, error) {
	if f.ReadErr != nil {
		return nil, f.ReadErr
	}
	if !f.Exists {
		return nil, ErrNotFound
	}
	return append([]byte(nil), f.Value...), nil
}

func (f *Fake) Write(_ context.Context, value []byte) error {
	if f.WriteErr != nil {
		return f.WriteErr
	}
	f.Value = append([]byte(nil), value...)
	f.Exists = true
	f.Writes++
	return nil
}
