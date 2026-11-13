package trustpicker

import "slices"

// Fake is a Picker for tests in other packages.
//
// Available returns IsAvailable. Pick records a copy of its options in Got,
// increments Calls, and returns Err if set, else a copy of Selection. A nil
// Selection is a confirm with nothing checked.
type Fake struct {
	IsAvailable bool
	Selection   []string
	Err         error

	Got   []Option
	Calls int
}

func (f *Fake) Available() bool { return f.IsAvailable }

func (f *Fake) Pick(opts []Option) ([]string, error) {
	f.Got = slices.Clone(opts)
	f.Calls++
	if f.Err != nil {
		return nil, f.Err
	}
	return append([]string{}, f.Selection...), nil
}
