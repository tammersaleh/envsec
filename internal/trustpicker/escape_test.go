package trustpicker

import (
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

func TestEscape(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"plain", "Private", "Private"},
		{"empty", "", ""},
		{"spaces kept", "My CI token", "My CI token"},
		{"printable unicode kept", "Tökens 日本", "Tökens 日本"},
		{"newline", "a\nb", `a\nb`},
		{"carriage return", "a\rb", `a\rb`},
		{"tab", "a\tb", `a\tb`},
		{"nul", "a\x00b", `a\x00b`},
		{"escape byte", "\x1b[31mred", `\x1b[31mred`},
		{"bell and backspace", "\a\b", `\x07\x08`},
		{"unit separator", "\x1f", `\x1f`},
		{"del", "a\x7fb", `a\x7fb`},
		{"c1 csi", "a\u009bb", `a\u009bb`},
		{"c1 first", "\u0080", `\u0080`},
		{"c1 last", "\u009f", `\u009f`},
		{"invalid utf8 byte", "a\xffb", `a\xffb`},
		{"truncated utf8", "a\xe2\x82", `a\xe2\x82`},
		{"raw c1 byte is invalid utf8", "\x9b", `\x9b`},
		{"bidi lre", "\u202a", `\u202a`},
		{"bidi rlo", "abc\u202edef", `abc\u202edef`},
		{"bidi isolate first", "\u2066", `\u2066`},
		{"bidi isolate pop", "\u2069", `\u2069`},
		{"line separator", "a\u2028b", `a\u2028b`},
		{"paragraph separator", "a\u2029b", `a\u2029b`},
		{"rtl mark", "\u200f", `\u200f`},
		{"zero width space", "a\u200bb", `a\u200bb`},
		{"byte order mark", "\ufeff", `\ufeff`},
		{"no-break space", "a\u00a0b", `a\u00a0b`},
		{"tag character", "\U000e0041", `\U000e0041`},
		{"backslash", `a\nb`, `a\\nb`},
		{
			"screen clear and fake prompt",
			"\x1b[2J[x] trusted\nConfirm?",
			`\x1b[2J[x] trusted\nConfirm?`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Escape(tt.in)
			if got != tt.want {
				t.Errorf("Escape(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestEscapeCap(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"at the cap", strings.Repeat("a", 60), strings.Repeat("a", 60)},
		{"one over", strings.Repeat("a", 61), strings.Repeat("a", 59) + "…"},
		{"long", strings.Repeat("a", 500), strings.Repeat("a", 59) + "…"},
		{"multibyte counts runes", strings.Repeat("日", 61), strings.Repeat("日", 59) + "…"},
		{
			"escapes count at their displayed width",
			strings.Repeat("\x1b", 15),
			strings.Repeat(`\x1b`, 15),
		},
		{
			"an escape is never split",
			strings.Repeat("\x1b", 16),
			strings.Repeat(`\x1b`, 14) + "…",
		},
		{
			"cap applies after escaping",
			strings.Repeat("a", 57) + "\n\n",
			strings.Repeat("a", 57) + `\n` + "…",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Escape(tt.in)
			if got != tt.want {
				t.Errorf("Escape = %q, want %q", got, tt.want)
			}
			if n := utf8.RuneCountInString(got); n > 60 {
				t.Errorf("displayed length = %d runes, want at most 60", n)
			}
		})
	}
}

// TestEscapeOutputIsAlwaysSafe feeds every byte and a spread of runes through
// Escape and checks the property the picker relies on: the result is valid
// UTF-8 made only of printable runes.
func TestEscapeOutputIsAlwaysSafe(t *testing.T) {
	var inputs []string
	for b := 0; b < 256; b++ {
		inputs = append(inputs, "a"+string([]byte{byte(b)})+"b")
	}
	for r := rune(0); r <= 0x2100; r++ {
		inputs = append(inputs, string(r))
	}
	for _, r := range []rune{0xd7ff, 0xe000, 0xfeff, 0xfff9, 0xfffd, 0xffff, 0xe0001, 0xe007f, 0x10ffff} {
		inputs = append(inputs, string(r))
	}
	for _, in := range inputs {
		got := Escape(in)
		if !utf8.ValidString(got) {
			t.Errorf("Escape(%q) = %q, not valid UTF-8", in, got)
		}
		for _, r := range got {
			if !unicode.IsPrint(r) {
				t.Errorf("Escape(%q) = %q, contains unprintable %U", in, got, r)
			}
		}
	}
}

func TestLabels(t *testing.T) {
	tests := []struct {
		name string
		opts []Option
		want []string
	}{
		{"none", nil, []string{}},
		{
			"one line per option",
			[]Option{
				{ID: "src_a", Var: "GITHUB_TOKEN", Account: "my.1password.com", Vault: "Private", Item: "CI"},
				{ID: "src_b", Var: "GRAFANA_TOKEN", Account: "team.1password.com", Vault: "Shared", Item: "Grafana"},
			},
			[]string{
				"GITHUB_TOKEN  my.1password.com / Private / CI",
				"GRAFANA_TOKEN  team.1password.com / Shared / Grafana",
			},
		},
		{
			"every part is escaped",
			[]Option{
				{ID: "src_a", Var: "A\nB", Account: "acct\x1b[2J", Vault: "v\u202e", Item: "\x1b[2J[x] trusted\nConfirm?"},
			},
			[]string{`A\nB  acct\x1b[2J / v\u202e / \x1b[2J[x] trusted\nConfirm?`},
		},
		{
			"identical lines get their id",
			[]Option{
				{ID: "src_a", Var: "TOKEN", Account: "my.1password.com", Vault: "Private", Item: "CI"},
				{ID: "src_b", Var: "OTHER", Account: "my.1password.com", Vault: "Private", Item: "CI"},
				{ID: "src_c", Var: "TOKEN", Account: "my.1password.com", Vault: "Private", Item: "CI"},
			},
			[]string{
				"TOKEN  my.1password.com / Private / CI  [src_a]",
				"OTHER  my.1password.com / Private / CI",
				"TOKEN  my.1password.com / Private / CI  [src_c]",
			},
		},
		{
			"lines that collide only after the cap get their id",
			[]Option{
				{ID: "src_a", Var: "TOKEN", Account: "a", Vault: "v", Item: strings.Repeat("x", 80) + "1"},
				{ID: "src_b", Var: "TOKEN", Account: "a", Vault: "v", Item: strings.Repeat("x", 80) + "2"},
			},
			[]string{
				"TOKEN  a / v / " + strings.Repeat("x", 59) + "…  [src_a]",
				"TOKEN  a / v / " + strings.Repeat("x", 59) + "…  [src_b]",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Labels(tt.opts)
			if len(got) != len(tt.want) {
				t.Fatalf("Labels returned %d lines, want %d: %q", len(got), len(tt.want), got)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("line %d = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}
