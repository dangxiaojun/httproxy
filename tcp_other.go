// +build !linux

package main

import (
	"net"
)

func setMark(conn *net.TCPConn, mark int) {
}
