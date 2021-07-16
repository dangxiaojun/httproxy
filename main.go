package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"github.com/dangxiaojun/httproxy/acl"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

var flags struct {
	BindAddr   string
	AccessFile string
	AclTest    string
	AclTestIP  string
	RateLimit  int
}

func main() {

	flag.IntVar(&flags.RateLimit, "r", 0, "rate limit")
	flag.StringVar(&flags.BindAddr, "b", "172.31.255.254:88", "bind address")
	flag.StringVar(&flags.AccessFile, "f", "", "access control rule file")
	flag.StringVar(&flags.AclTest, "t", "", "test domain by access rule")
	flag.StringVar(&flags.AclTestIP, "tip", "", "test domain by access rule")
	flag.Parse()

	log.SetPrefix("TRACE ")
	log.SetOutput(os.Stdout)
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// read domain list
	if flags.AccessFile != "" {
		if err := acl.Parse(flags.AccessFile); err != nil {
			log.Fatalf("解析配置文件出错")
		}
	}

	// test
	if flags.AclTest != "" {
		acl.Test(flags.AclTest, flags.AclTestIP)
		return
	}

	sigCh := make(chan os.Signal, 1)
	go func() {
		for {
			// signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, os.Interrupt, os.Kill)
			signal.Notify(sigCh, syscall.SIGHUP)
			if s := <-sigCh; s != syscall.SIGHUP {
				break
			}
			if err := acl.Parse(flags.AccessFile); err != nil {
				log.Printf("重新加载配置文件出错: %v", err)
			} else {
				log.Printf("重新加载配置文件成功, 使用[-t]选项进行新配置测试")
			}
		}
	}()

	if err := serve(flags.BindAddr); err != nil {
		log.Fatalf("启动监听失败: %v", err)
	}
}

func serve(addr string) error {
	a, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	var errCancel error
	listener := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				if flags.RateLimit > 0 {
					if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, flags.RateLimit); err != nil {
						errCancel = err
						cancel()
					}
				}
			})
		},
	}

	l, err := listener.Listen(ctx, "tcp", a.String())
	if err != nil {
		if errCancel != nil {
			err = errCancel
		}
		return err
	}

	for {
		conn, err := l.Accept()
		if err != nil {
			log.Printf("接收链接失败: %s", err)
			continue
		}

		c := conn.(*net.TCPConn)

		go func() {
			defer c.Close()
			// 读取起源目标地址
			dest, err := GetOrigDst(c, false)
			if err != nil {
				log.Printf("从[%s]读取起源目标地址失败: %v", c.RemoteAddr(), err)
				return
			}
			origDestAddr, origDestPort, err := net.SplitHostPort(dest.String())
			if err != nil {
				log.Printf("从[%s]解析起源地址[%s]失败: %s", c.RemoteAddr(), dest, err)
				return
			}

			domain, header, err, err2 := parseDomain(c, origDestPort)
			domainDetail := domain
			if err2 != nil {
				log.Printf("从[%s > %s]读取数据失败: %v", c.RemoteAddr(), dest, err2)
				return
			}
			if err != nil {
				domainDetail = fmt.Sprintf("没有读取到域名: %v", err)
			}

			r := acl.GetReport(domain, origDestAddr)
			if r.Black {
				log.Printf("从[%s]转发域名[%s]命中黑名单规则，本条链接被阻断", c.RemoteAddr(), domain)
				return
			}
			// 域名重解析
			if r.ReDns != "" {
				dns := &net.Resolver{
					PreferGo: true,
					Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
						d := net.Dialer{
							Timeout: 10 * time.Second,
						}
						return d.DialContext(ctx, "udp", r.ReDns)
					},
				}
				addrs, err := dns.LookupHost(context.Background(), domain)
				if err != nil {
					log.Printf("从[%s]转发域名[%s]重新解析DNS失败: %v", c.RemoteAddr(), domain, err)
					return
				}
				if len(addrs) == 0 {
					log.Printf("从[%s]转发域名[%s]重新解析DNS失败: 没有解析到可用的结果", c.RemoteAddr(), domain)
					return
				}
				r.RedirectAddr = addrs[0]
			}

			// relay
			remoteAddr := net.JoinHostPort(r.RedirectAddr, origDestPort)
			rc, err := createRemote(remoteAddr, r.Mark)
			if err != nil {
				log.Printf("链接目标[%s] > [%s](%s)失败: %v", c.RemoteAddr(), remoteAddr, domainDetail, err)
				return
			}
			defer rc.Close()

			// relay
			log.Printf("转发 [%s > %s > %s(%s)]", c.RemoteAddr(), rc.LocalAddr(), rc.RemoteAddr(), domainDetail)
			_, err = io.Copy(rc, bytes.NewReader(header))
			if err != nil && err != net.ErrClosed {
				log.Printf("转发 [%s > %s > %s(%s)] header出现错误: %v", c.RemoteAddr(), rc.LocalAddr(), rc.RemoteAddr(), domainDetail, err)
			}
			if err := relay(rc.(*net.TCPConn), c); err != nil {
				log.Printf("转发 [%s > %s > %s(%s)] 出现错误: %v", c.RemoteAddr(), rc.LocalAddr(), rc.RemoteAddr(), domainDetail, err)
			}
		}()
	}
}

func createRemote(addr string, mark int) (net.Conn, error) {
	a, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("目标地址不是一个有效得地址: %v", err)
	}

	var errCancel error
	ctx, cancel := context.WithCancel(context.Background())
	dialer := &net.Dialer{
		Control: func(_, _ string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, mark); err != nil {
					errCancel = err
					cancel()
				}
				// buf实际大小算法， 如果不进行设置，将按照一下两个文件设置buf大小
				// 从/proc/sys/net/ipv4/tcp_wmem 写缓冲 得到最小值 默认值 最大值
				// 从/proc/sys/net/ipv4/tcp_rmem 读缓冲 得到最小值 默认值 最大值
				// (1) val > 最大值sysctl_rmem_max， 则设置为最大值得2倍
				// (2) val*2 < 最小值，则设置为最小值
				// (3) val < 最大值sysctl_rmem_max，并且val*2 > 最小值，则设置为val*2
				if flags.RateLimit > 0 {
					if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, flags.RateLimit); err != nil {
						errCancel = err
						cancel()
					}
				}
			})
		},
	}

	rc, err := dialer.DialContext(ctx, "tcp", a.String())
	if err != nil {
		if errCancel != nil {
			err = errCancel
		}
		return nil, err
	}
	return rc, nil
}

func relay(left, right *net.TCPConn) error {
	defer left.Close()
	defer right.Close()
	var err error
	var err1 error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer left.Close()
		_, err = io.Copy(left, right)
	}()
	_, err1 = io.Copy(right, left)
	wg.Wait()

	if err != nil && !errors.Is(err, net.ErrClosed) {
		return err
	}
	if err1 != nil && !errors.Is(err1, net.ErrClosed) {
		return err1
	}
	return nil
}

func readHeader(r *net.TCPConn) ([]byte, error) {
	buf := make([]byte, 16384)
	n, err := r.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("read header failed: %s", err)
	}
	return buf[:n], nil
}

func parseDomain(r *net.TCPConn, port string) (string, []byte, error, error) {
	switch port {
	case "80":
		return parseDomainHttp(r)
	case "443":
		return parseDomainHttps(r)
	default:
		return "", nil, fmt.Errorf("非80，443端口数据"), nil
	}
}

func parseDomainHttp(r *net.TCPConn) (string, []byte, error, error) {
	header, err := readHeader(r)
	if err != nil {
		return "", nil, nil, err
	}

	// read all header
	reg := regexp.MustCompile(`(?i:host):.*\r\n`)
	domains := reg.FindAllString(string(header), -1)
	if domains == nil {
		return "", header, fmt.Errorf("not found Host field"), nil
	}
	domain := strings.TrimRight(strings.Split(domains[0], ":")[1], "\r\n")
	domain = strings.TrimLeft(domain, " ")
	return domain, header, nil, nil
}

func parseDomainHttps(r *net.TCPConn) (string, []byte, error, error) {
	/* 1   TLS_HANDSHAKE_CONTENT_TYPE
	 * 1   TLS major version
	 * 1   TLS minor version
	 * 2   TLS Record length
	 * --------------
	 * 1   Handshake type
	 * 3   Length
	 * 2   Version
	 * 32  Random
	 * 1   Session ID length
	 * ?   Session ID
	 * 2   Cipher Suites length
	 * ?   Cipher Suites
	 * 1   Compression Methods length
	 * ?   Compression Methods
	 * 2   Extensions length
	 * ---------------
	 * 2   Extension data length
	 * 2   Extension type (0x0000 for server_name)
	 * ---------------
	 * 2   server_name list length
	 * 1   server_name type (0)
	 * 2   server_name length
	 * ?   server_name
	 */
	header, err := readHeader(r)
	if err != nil {
		return "", nil, nil, err
	}

	const (
		DOMAINLEN                   = 256
		TLSHEADERLEN                = 5
		FIXEDLENGTHRECORDS          = 38
		TLSHANDSHAKECONTENTTYPE     = 0x16
		TLSHANDSHAKETYPECLIENTHELLO = 0x01
	)

	length := len(header)
	pos := 0
	if length < TLSHEADERLEN+FIXEDLENGTHRECORDS {
		return "", header, fmt.Errorf("tls header: not enough data"), nil
	}
	if int(header[0])&0x80 != 0 && int(header[2]) == 1 {
		return "", header, fmt.Errorf("tls header: SSL 2.0, does not support SNI"), nil
	}
	if header[0] != TLSHANDSHAKECONTENTTYPE {
		return "", header, fmt.Errorf("tls header: tls content type not 0x16"), nil
	}
	if header[1] < 3 {
		return "", header, fmt.Errorf("tls header: TLS major version < 3, does not support SNI"), nil
	}
	recordLen := int(header[3])<<8 + int(header[4]) + TLSHEADERLEN
	if length < recordLen {
		return "", header, fmt.Errorf("tls header: not enough data2"), nil
	}
	if header[TLSHEADERLEN] != TLSHANDSHAKETYPECLIENTHELLO {
		return "", header, fmt.Errorf("tls header: invalid handshake type"), nil
	}

	pos += TLSHEADERLEN + FIXEDLENGTHRECORDS
	// skip session ID
	if pos+1 > length || pos+1+int(header[pos]) > length {
		return "", header, fmt.Errorf("tls header: not enough data3"), nil
	}
	pos += 1 + int(header[pos])
	// skip cipher suites
	if pos+2 > length || (pos+2+(int(header[pos])<<8)+int(header[pos+1]) > length) {
		return "", header, fmt.Errorf("tls header: not enough data4"), nil
	}
	pos += 2 + (int(header[pos]) << 8) + int(header[pos+1])
	// skip compression methods
	if pos+1 > length || pos+1+int(header[pos]) > length {
		return "", header, fmt.Errorf("tls header: not enough data5"), nil
	}
	pos += 1 + int(header[pos])
	// skip extension length
	if pos+2 > length {
		return "", header, fmt.Errorf("tls header: not enough data6"), nil
	}
	pos += 2

	// parse extension data
	for {
		if pos+4 > recordLen {
			return "", header, fmt.Errorf("tls header: buffer more than one record, SNI still not found"), nil
		}
		if pos+4 > length {
			return "", header, fmt.Errorf("tls header: not enough data7"), nil
		}
		extDataLen := (int(header[pos+2]) << 8) + int(header[pos+3])
		if int(header[pos]) == 0 && int(header[pos+1]) == 0 {
			// server_name extension type
			pos += 4
			if pos+5 > length {
				return "", header, fmt.Errorf("tls header: not server_name list header"), nil
			}
			serverNameLen := (int(header[pos+3]) << 8) + int(header[pos+4])
			if pos+5+serverNameLen > length {
				return "", header, fmt.Errorf("tls header: not server_name list header"), nil
			}
			// return server_name
			if serverNameLen+1 > DOMAINLEN {
				return "", header, fmt.Errorf("tls header: The domain name is too long"), nil
			}
			serverName := header[pos+5 : pos+5+serverNameLen]
			return string(serverName), header, nil, nil
		} else {
			// skip
			pos += 4 + extDataLen
		}
	}
}
