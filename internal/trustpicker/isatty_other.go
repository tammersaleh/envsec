//go:build !darwin && !linux

package trustpicker

// isTerminal is false where envsec does not ship.
func isTerminal(uintptr) bool { return false }
