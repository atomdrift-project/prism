// SO_REUSEPORT_LB is FreeBSD's connection-load-balancing variant of
// SO_REUSEPORT: multiple processes can bind the same address, and the
// kernel hash-distributes inbound connections across the open listeners.
// We use it for zero-downtime deploys: the rollout script starts the new
// prism alongside the old one, both bound to the same port, then SIGTERMs
// the old one. The kernel keeps routing new connections to the survivor
// during the brief overlap, so users never see a connection-refused.

package main

import (
	"syscall"

	"golang.org/x/sys/unix"
)

func setReusePort(fd uintptr) error {
	return syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, unix.SO_REUSEPORT_LB, 1)
}
