package trustpicker

import (
	"syscall"
	"unsafe"
)

// isTerminal reports whether fd is a terminal. It asks for the termios, which
// only a terminal has. A mode check is not enough: /dev/null is a character
// device too.
func isTerminal(fd uintptr) bool {
	var t syscall.Termios
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TIOCGETA, uintptr(unsafe.Pointer(&t)))
	return errno == 0
}
