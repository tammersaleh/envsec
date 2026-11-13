package trustpicker

import (
	"context"
	"fmt"
	"io"
	"os"
	"slices"

	"charm.land/huh/v2"
)

// Terminal is the real Picker. It draws on out and reads keys from in.
type Terminal struct {
	in  io.Reader
	out io.Writer
}

// New returns a Picker that reads keys from in and draws on out. The commands
// pass os.Stdin and os.Stderr. Nothing is ever written to stdout.
func New(in io.Reader, out io.Writer) *Terminal {
	return &Terminal{in: in, out: out}
}

// Available is true only when in and out are both terminals. A dumb terminal
// does not count: it cannot draw the list.
func (t *Terminal) Available() bool {
	in, ok := t.in.(*os.File)
	if !ok || in == nil {
		return false
	}
	out, ok := t.out.(*os.File)
	if !ok || out == nil {
		return false
	}
	return os.Getenv("TERM") != "dumb" && isTerminal(in.Fd()) && isTerminal(out.Fd())
}

// Pick shows the list and blocks until the user confirms or cancels. Space
// toggles, enter confirms, and Ctrl-C, Ctrl-D, or Esc cancels. The end of in
// or a read error on it also cancels.
func (t *Terminal) Pick(opts []Option) ([]string, error) {
	if err := checkOptions(opts); err != nil {
		return nil, err
	}
	if len(opts) == 0 {
		return []string{}, nil
	}

	labels := Labels(opts)
	choices := make([]huh.Option[int], len(opts))
	for i, o := range opts {
		choices[i] = huh.NewOption(labels[i], i).Selected(o.Checked)
	}
	var checked []int
	// The heading sits on the group. huh 2.0.3 sizes a list as its option
	// count minus its own title and description lines, which hides options.
	list := huh.NewMultiSelect[int]().
		Options(choices...).
		Filterable(false).
		Validate(func(idx []int) error { return CheckSelection(opts, idx) }).
		Value(&checked)

	// bubbletea swallows EOF on its input and would wait forever. The
	// watched reader cancels the form instead.
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)

	group := huh.NewGroup(list).
		Title("Trusted sources").
		Description("space toggles, enter confirms, esc cancels")
	// NewForm turns on accessible mode when TERM is dumb. That mode drops
	// read errors and cannot tell EOF from a confirm, so it stays off.
	form := huh.NewForm(group).
		WithKeyMap(keyMap()).
		WithAccessible(false).
		WithInput(watch(t.in, cancel)).
		WithOutput(t.out)

	err := form.RunWithContext(ctx)
	if form.State != huh.StateCompleted {
		if cause := context.Cause(ctx); cause != nil {
			err = cause
		}
		if err == nil {
			return nil, ErrCancelled
		}
		return nil, fmt.Errorf("%w: %v", ErrCancelled, err)
	}

	slices.Sort(checked)
	ids := make([]string, 0, len(checked))
	for _, i := range checked {
		ids = append(ids, opts[i].ID)
	}
	return ids, nil
}

// keyMap is huh's default with three changes: Ctrl-D and Esc cancel like
// Ctrl-C, and select-all is unbound so one key cannot trust every source.
// A binding with no keys never matches, and huh cannot switch it back on.
func keyMap() *huh.KeyMap {
	km := huh.NewDefaultKeyMap()
	km.Quit.SetKeys("ctrl+c", "ctrl+d", "esc")
	km.Quit.SetHelp("esc", "cancel")
	km.MultiSelect.Toggle.SetHelp("space", "toggle")
	km.MultiSelect.Next.SetHelp("enter", "confirm")
	km.MultiSelect.Submit.SetHelp("enter", "confirm")
	km.MultiSelect.HalfPageDown.SetKeys("pgdown")
	km.MultiSelect.HalfPageDown.SetHelp("pgdn", "½ page down")
	km.MultiSelect.HalfPageUp.SetKeys("pgup")
	km.MultiSelect.HalfPageUp.SetHelp("pgup", "½ page up")
	km.MultiSelect.SelectAll.SetKeys()
	km.MultiSelect.SelectNone.SetKeys()
	return km
}

// watch wraps r so the first read error, EOF included, calls cancel. An
// *os.File keeps its Fd so bubbletea still puts the terminal in raw mode.
func watch(r io.Reader, cancel context.CancelCauseFunc) io.Reader {
	if f, ok := r.(*os.File); ok {
		return &watchedFile{File: f, cancel: cancel}
	}
	return &watchedReader{r: r, cancel: cancel}
}

type watchedFile struct {
	*os.File
	cancel context.CancelCauseFunc
}

func (w *watchedFile) Read(p []byte) (int, error) {
	n, err := w.File.Read(p)
	if err != nil {
		w.cancel(fmt.Errorf("reading keys: %w", err))
	}
	return n, err
}

type watchedReader struct {
	r      io.Reader
	cancel context.CancelCauseFunc
}

func (w *watchedReader) Read(p []byte) (int, error) {
	n, err := w.r.Read(p)
	if err != nil {
		w.cancel(fmt.Errorf("reading keys: %w", err))
	}
	return n, err
}
