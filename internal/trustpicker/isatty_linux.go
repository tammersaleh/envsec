package trustpicker

import (
	"syscall"
	"unsafe"
)

// isTerminal reports whether fd is a terminal. CI runs on Linux.
func isTerminal(fd uintptr) bool {
	var t syscall.Termios
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TCGETS, uintptr(unsafe.Pointer(&t)))
	return errno == 0
}
