// +build !linux,!darwin

package main

import (
	"net"
)

func setMark(conn *net.TCPConn, mark int) {
}
