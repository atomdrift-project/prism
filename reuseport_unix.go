//go:build (darwin || linux) && !freebsd

// Plain SO_REUSEPORT: lets multiple processes bind the same port. Linux
// hashes connections across listeners similarly to FreeBSD's _LB variant
// for non-listening (UDP) sockets and accept-equalizes for TCP; macOS
// allows the binding so the dev loop matches the deploy target.

package main

import (
	"syscall"

	"golang.org/x/sys/unix"
)

func setReusePort(fd uintptr) error {
	// fd comes from syscall.RawConn.Control, i.e. a kernel file descriptor:
	// always a small non-negative int, never large enough to truncate.
	return syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, unix.SO_REUSEPORT, 1)
}
