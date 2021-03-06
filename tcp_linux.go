// +build linux

package main

import (
	"syscall"
)

func setMark(fd int, mark int) error {
	return syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_MARK, mark)
}
