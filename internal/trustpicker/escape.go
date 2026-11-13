package trustpicker

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// maxDisplayRunes caps one escaped string, ellipsis included.
const maxDisplayRunes = 60

const ellipsis = "…"

// Escape makes s safe to draw on one terminal line. Account, vault, and item
// names come from 1Password, and anyone who can write to a shared vault picks
// them.
//
// Every rune that is not printable is replaced with a visible escape: C0, DEL,
// C1, bidi overrides and isolates, line and paragraph separators, zero-width
// and other format characters, and every space except U+0020. An invalid
// UTF-8 byte becomes \xNN. A backslash is doubled so an escape cannot be
// forged. The result is at most 60 runes and ends in an ellipsis when cut. An
// escape is never cut in half.
func Escape(s string) string {
	var tokens []string
	total := 0
	for len(s) > 0 {
		r, size := utf8.DecodeRuneInString(s)
		tok := escapeRune(r, s[:size])
		s = s[size:]
		tokens = append(tokens, tok)
		total += utf8.RuneCountInString(tok)
	}
	if total <= maxDisplayRunes {
		return strings.Join(tokens, "")
	}
	var b strings.Builder
	room := maxDisplayRunes - utf8.RuneCountInString(ellipsis)
	for _, tok := range tokens {
		n := utf8.RuneCountInString(tok)
		if n > room {
			break
		}
		room -= n
		b.WriteString(tok)
	}
	b.WriteString(ellipsis)
	return b.String()
}

// escapeRune returns the display form of one decoded rune. raw is the bytes
// it was decoded from, which tells an invalid byte from a real U+FFFD.
func escapeRune(r rune, raw string) string {
	switch {
	case r == utf8.RuneError && len(raw) == 1:
		return fmt.Sprintf(`\x%02x`, raw[0])
	case r == '\\':
		return `\\`
	case r == '\n':
		return `\n`
	case r == '\r':
		return `\r`
	case r == '\t':
		return `\t`
	case unicode.IsPrint(r):
		return string(r)
	case r < 0x80:
		return fmt.Sprintf(`\x%02x`, r)
	case r <= 0xffff:
		return fmt.Sprintf(`\u%04x`, r)
	default:
		return fmt.Sprintf(`\U%08x`, r)
	}
}

// Labels returns the line shown for each option, in order. Every part is
// escaped. Lines that would be identical get the option id appended, because
// huh toggles options by their text.
func Labels(opts []Option) []string {
	labels := make([]string, len(opts))
	count := make(map[string]int, len(opts))
	for i, o := range opts {
		labels[i] = fmt.Sprintf("%s  %s / %s / %s",
			Escape(o.Var), Escape(o.Account), Escape(o.Vault), Escape(o.Item))
		count[labels[i]]++
	}
	for i, o := range opts {
		if count[labels[i]] > 1 {
			labels[i] += "  [" + Escape(o.ID) + "]"
		}
	}
	return labels
}
