package trustpicker

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

var threeOpts = []Option{
	{ID: "src_a", Var: "TOKEN", Account: "my.1password.com", Vault: "Private", Item: "CI"},
	{ID: "src_b", Var: "TOKEN", Account: "team.1password.com", Vault: "Shared", Item: "CI"},
	{ID: "src_c", Var: "OTHER", Account: "my.1password.com", Vault: "Private", Item: "Other"},
}

func TestCheckSelection(t *testing.T) {
	tests := []struct {
		name    string
		opts    []Option
		checked []int
		wantErr string
	}{
		{"nothing checked", threeOpts, nil, ""},
		{"one checked", threeOpts, []int{0}, ""},
		{"different vars", threeOpts, []int{0, 2}, ""},
		{"other pairing of different vars", threeOpts, []int{1, 2}, ""},
		{"same var twice", threeOpts, []int{0, 1}, "TOKEN is checked twice, keep one"},
		{"same var twice among others", threeOpts, []int{2, 1, 0}, "TOKEN is checked twice, keep one"},
		{
			"first repeated var in list order is named",
			[]Option{{ID: "1", Var: "B"}, {ID: "2", Var: "A"}, {ID: "3", Var: "A"}, {ID: "4", Var: "B"}},
			[]int{3, 2, 1, 0},
			"A is checked twice, keep one",
		},
		{
			"var name is escaped in the message",
			[]Option{{ID: "1", Var: "A\x1b[2J"}, {ID: "2", Var: "A\x1b[2J"}},
			[]int{0, 1},
			`A\x1b[2J is checked twice, keep one`,
		},
		{"out of range index is ignored", threeOpts, []int{0, 7, -1}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckSelection(tt.opts, tt.checked)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || err.Error() != tt.wantErr {
				t.Fatalf("error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestCheckOptions(t *testing.T) {
	tests := []struct {
		name    string
		opts    []Option
		wantErr string
	}{
		{"none", nil, ""},
		{"unique ids", threeOpts, ""},
		{"empty id", []Option{{ID: ""}}, "option 0 has no id"},
		{"repeated id", []Option{{ID: "src_a"}, {ID: "src_b"}, {ID: "src_a"}}, `option id "src_a" is repeated`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkOptions(tt.opts)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want it to contain %q", err, tt.wantErr)
			}
			if errors.Is(err, ErrCancelled) {
				t.Error("a caller bug must not look like a cancel")
			}
		})
	}
}

func TestFake(t *testing.T) {
	boom := fmt.Errorf("%w: boom", ErrCancelled)
	tests := []struct {
		name    string
		fake    *Fake
		wantIDs []string
		wantErr error
	}{
		{"canned selection", &Fake{IsAvailable: true, Selection: []string{"src_c", "src_a"}}, []string{"src_c", "src_a"}, nil},
		{"confirm with nothing checked", &Fake{IsAvailable: true}, []string{}, nil},
		{"cancel", &Fake{IsAvailable: true, Err: ErrCancelled}, nil, ErrCancelled},
		{"wrapped cancel", &Fake{IsAvailable: true, Err: boom, Selection: []string{"src_a"}}, nil, boom},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var p Picker = tt.fake
			if !p.Available() {
				t.Error("Available() = false, want true")
			}
			ids, err := p.Pick(threeOpts)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if tt.wantErr != nil && !errors.Is(err, ErrCancelled) {
				t.Errorf("err = %v, want it to match ErrCancelled", err)
			}
			if tt.wantErr == nil && ids == nil {
				t.Error("a confirm must return a non-nil slice")
			}
			if tt.wantErr != nil && ids != nil {
				t.Errorf("ids = %v on error, want nil", ids)
			}
			if tt.wantErr == nil && !reflect.DeepEqual(ids, tt.wantIDs) {
				t.Errorf("ids = %v, want %v", ids, tt.wantIDs)
			}
			if tt.fake.Calls != 1 {
				t.Errorf("Calls = %d, want 1", tt.fake.Calls)
			}
			if !reflect.DeepEqual(tt.fake.Got, threeOpts) {
				t.Errorf("Got = %v, want the options passed in", tt.fake.Got)
			}
		})
	}
}

func TestFakeUnavailable(t *testing.T) {
	f := &Fake{}
	if f.Available() {
		t.Error("zero Fake is available, want unavailable")
	}
	if f.Calls != 0 || f.Got != nil {
		t.Error("Available must not record a Pick")
	}
}

func TestFakeCopies(t *testing.T) {
	f := &Fake{IsAvailable: true, Selection: []string{"src_a"}}
	opts := []Option{{ID: "src_a", Var: "TOKEN"}}
	ids, _ := f.Pick(opts)
	opts[0].Var = "CHANGED"
	ids[0] = "changed"
	if f.Got[0].Var != "TOKEN" {
		t.Error("Fake kept the caller's slice, want a copy")
	}
	if f.Selection[0] != "src_a" {
		t.Error("Fake returned its own slice, want a copy")
	}
}
