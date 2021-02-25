// +build linux

package main

import (
	"net"
	"syscall"
)

func setMark(conn *net.TCPConn, mark int) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return
	}
	_ = raw.Control(func(fd uintptr) {
		_ = syscall.SetsockoptByte(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, byte(mark))
	})
	return
}
