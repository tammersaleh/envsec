package trustpicker

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// These tests drive the real huh form through an io.Pipe and a buffer. No
// terminal is involved, so raw mode, window size, and what a person sees are
// not covered here.

const (
	keySpace = " "
	keyEnter = "\r"
	keyDown  = "j"
	keyCtrlC = "\x03"
	keyCtrlD = "\x04"
	keyEsc   = "\x1b"

	// sizeReport is what a terminal answers when asked for its size in
	// cells. Without a size bubbletea draws nothing, and a buffer has none.
	sizeReport = "\x1b[8;24;100t"
)

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type pickResult struct {
	ids []string
	err error
}

// startPick runs Pick in the background. The returned writer is the keyboard.
// A 100x24 size report is sent first so the form is drawn.
func startPick(t *testing.T, opts []Option) (*io.PipeWriter, *lockedBuffer, <-chan pickResult) {
	t.Helper()
	pr, pw := io.Pipe()
	t.Cleanup(func() { pw.Close() })
	out := &lockedBuffer{}
	done := make(chan pickResult, 1)
	go func() {
		ids, err := New(pr, out).Pick(opts)
		done <- pickResult{ids, err}
	}()
	io.WriteString(pw, sizeReport)
	return pw, out, done
}

func wait(t *testing.T, done <-chan pickResult) pickResult {
	t.Helper()
	select {
	case r := <-done:
		return r
	case <-time.After(10 * time.Second):
		t.Fatal("Pick did not return")
		return pickResult{}
	}
}

// stillOpen fails the test if Pick returns within a short window.
func stillOpen(t *testing.T, done <-chan pickResult) {
	t.Helper()
	select {
	case r := <-done:
		t.Fatalf("Pick returned early: ids=%v err=%v", r.ids, r.err)
	case <-time.After(300 * time.Millisecond):
	}
}

func waitForOutput(t *testing.T, out *lockedBuffer, want string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(out.String(), want) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("output never contained %q:\n%q", want, out.String())
}

func TestPickConfirm(t *testing.T) {
	tests := []struct {
		name string
		opts []Option
		keys []string
		want []string
	}{
		{"nothing checked", threeOpts, []string{keyEnter}, []string{}},
		{"check the first", threeOpts, []string{keySpace, keyEnter}, []string{"src_a"}},
		{
			"check first and third, returned in input order",
			threeOpts,
			[]string{keyDown, keyDown, keySpace, "k", "k", keySpace, keyEnter},
			[]string{"src_a", "src_c"},
		},
		{
			"pre-checked options are kept",
			[]Option{
				{ID: "src_a", Var: "A", Checked: true},
				{ID: "src_b", Var: "B"},
				{ID: "src_c", Var: "C", Checked: true},
			},
			[]string{keyEnter},
			[]string{"src_a", "src_c"},
		},
		{
			"unchecking revokes",
			[]Option{
				{ID: "src_a", Var: "A", Checked: true},
				{ID: "src_b", Var: "B", Checked: true},
			},
			[]string{keySpace, keyEnter},
			[]string{"src_b"},
		},
		{
			"unchecking everything is an empty confirm",
			[]Option{{ID: "src_a", Var: "A", Checked: true}},
			[]string{keySpace, keyEnter},
			[]string{},
		},
		{
			"select all is not bound",
			threeOpts,
			[]string{"\x01", keyEnter},
			[]string{},
		},
		{
			"identical lines toggle one at a time",
			[]Option{
				{ID: "src_a", Var: "A", Account: "x", Vault: "y", Item: "z"},
				{ID: "src_b", Var: "A", Account: "x", Vault: "y", Item: "z"},
			},
			[]string{keySpace, keyEnter},
			[]string{"src_a"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pw, _, done := startPick(t, tt.opts)
			for _, k := range tt.keys {
				io.WriteString(pw, k)
			}
			r := wait(t, done)
			if r.err != nil {
				t.Fatalf("err = %v, want nil", r.err)
			}
			if r.ids == nil {
				t.Fatal("ids = nil, want a non-nil slice on confirm")
			}
			if !reflect.DeepEqual(r.ids, tt.want) {
				t.Errorf("ids = %v, want %v", r.ids, tt.want)
			}
		})
	}
}

func TestPickCancel(t *testing.T) {
	tests := []struct {
		name string
		send func(pw *io.PipeWriter)
	}{
		{"ctrl-c", func(pw *io.PipeWriter) { io.WriteString(pw, keyCtrlC) }},
		{"ctrl-d", func(pw *io.PipeWriter) { io.WriteString(pw, keyCtrlD) }},
		{"esc", func(pw *io.PipeWriter) { io.WriteString(pw, keyEsc) }},
		{"eof", func(pw *io.PipeWriter) { pw.Close() }},
		{"read error", func(pw *io.PipeWriter) { pw.CloseWithError(errors.New("tty went away")) }},
		{"ctrl-c after checking", func(pw *io.PipeWriter) { io.WriteString(pw, keySpace+keyCtrlC) }},
		{"eof after checking", func(pw *io.PipeWriter) {
			io.WriteString(pw, keySpace)
			pw.Close()
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pw, _, done := startPick(t, threeOpts)
			tt.send(pw)
			r := wait(t, done)
			if !errors.Is(r.err, ErrCancelled) {
				t.Fatalf("err = %v, want ErrCancelled", r.err)
			}
			if r.ids != nil {
				t.Errorf("ids = %v, want nil on cancel", r.ids)
			}
		})
	}
}

func TestPickEmptyInput(t *testing.T) {
	// A reader that is already at EOF, as with stdin from /dev/null.
	ids, err := New(strings.NewReader(""), io.Discard).Pick(threeOpts)
	if !errors.Is(err, ErrCancelled) {
		t.Fatalf("err = %v, want ErrCancelled", err)
	}
	if ids != nil {
		t.Errorf("ids = %v, want nil", ids)
	}
}

func TestPickRefusesSameVarTwice(t *testing.T) {
	pw, out, done := startPick(t, threeOpts)
	// Check src_a and src_b, both TOKEN, and try to confirm.
	io.WriteString(pw, keySpace+keyDown+keySpace+keyEnter)
	waitForOutput(t, out, "TOKEN is checked twice, keep one")
	stillOpen(t, done)
	// Uncheck src_b. The confirm now goes through.
	io.WriteString(pw, keySpace+keyEnter)
	r := wait(t, done)
	if r.err != nil {
		t.Fatalf("err = %v, want nil", r.err)
	}
	if want := []string{"src_a"}; !reflect.DeepEqual(r.ids, want) {
		t.Errorf("ids = %v, want %v", r.ids, want)
	}
}

func TestPickShowsEscapedLabels(t *testing.T) {
	opts := []Option{{
		ID:      "src_a",
		Var:     "TOKEN",
		Account: "my.1password.com",
		Vault:   "Private",
		Item:    "\x1b[2J[x] trusted\nConfirm?",
	}}
	pw, out, done := startPick(t, opts)
	waitForOutput(t, out, `\x1b[2J[x] trusted\nConfirm?`)
	io.WriteString(pw, keyEnter)
	wait(t, done)
	got := out.String()
	if strings.Contains(got, "\x1b[2J[x]") {
		t.Errorf("raw item title reached the terminal:\n%q", got)
	}
	if !strings.Contains(got, "TOKEN") || !strings.Contains(got, "my.1password.com") || !strings.Contains(got, "Private") {
		t.Errorf("line is missing a part:\n%q", got)
	}
}

func TestPickNeverWritesStdout(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stdout")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stdout
	os.Stdout = f
	t.Cleanup(func() { os.Stdout = saved })

	pw, out, done := startPick(t, threeOpts)
	io.WriteString(pw, keySpace+keyEnter)
	r := wait(t, done)
	os.Stdout = saved
	f.Close()

	if r.err != nil {
		t.Fatalf("err = %v", r.err)
	}
	if out.String() == "" {
		t.Error("nothing was drawn on the picker's writer")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("stdout got %d bytes: %q", len(got), got)
	}
}

func TestPickNoOptions(t *testing.T) {
	ids, err := New(strings.NewReader(""), io.Discard).Pick(nil)
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if ids == nil || len(ids) != 0 {
		t.Errorf("ids = %#v, want an empty non-nil slice", ids)
	}
}

func TestPickRejectsBadOptions(t *testing.T) {
	_, err := New(strings.NewReader(""), io.Discard).Pick([]Option{{ID: "src_a"}, {ID: "src_a"}})
	if err == nil {
		t.Fatal("err = nil, want an error for a repeated id")
	}
	if errors.Is(err, ErrCancelled) {
		t.Errorf("err = %v, must not match ErrCancelled", err)
	}
}

func TestAvailable(t *testing.T) {
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer devNull.Close()
	regular, err := os.Create(filepath.Join(t.TempDir(), "f"))
	if err != nil {
		t.Fatal(err)
	}
	defer regular.Close()
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer pr.Close()
	defer pw.Close()

	tests := []struct {
		name string
		in   io.Reader
		out  io.Writer
	}{
		{"not files", strings.NewReader(""), io.Discard},
		{"nil", nil, nil},
		{"nil files", (*os.File)(nil), (*os.File)(nil)},
		{"dev null is a character device but not a terminal", devNull, devNull},
		{"regular file", regular, regular},
		{"pipe", pr, pw},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if New(tt.in, tt.out).Available() {
				t.Error("Available() = true, want false")
			}
		})
	}
}
