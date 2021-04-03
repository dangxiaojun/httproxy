package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"
)

const (
	remoteHttpPort  string = "80"
	remoteHttpsPort string = "443"
)

type (
	rule struct {
		Pattern *regexp.Regexp
		GuiseIP string
		ReadIP  string
		Dns     string
		Mark    string
		Black   string
	}
	errRule struct {
		Lineno int
		Raw    string
		Err    error
	}
	readDomainFunc func(*net.TCPConn) (string, []byte, error)
)

var rules []rule
var errRules []errRule

func main() {

	var flags struct {
		BindAddr   string
		AccessFile string
	}

	flag.StringVar(&flags.BindAddr, "b", "172.31.255.254:88", "bind address")
	flag.StringVar(&flags.AccessFile, "f", "access.list", "access control rule file")
	flag.Parse()

	log.SetPrefix("TRACE ")
	log.SetOutput(os.Stdout)
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// read domain list
	f, err := os.OpenFile(flags.AccessFile, os.O_RDONLY, 0600)
	if err != nil {
		log.Fatalf("无法读取配置文件: %v", err)
	}
	rBuf, err := ioutil.ReadAll(f)
	if err != nil && err != io.EOF {
		log.Fatalf("无法读取配置文件: %v", err)
	}
	ruleList := strings.Split(string(rBuf), "\n")

	log.Println("开始解析配置文件")
	for i, v := range ruleList[1:] {
		if v == "" {
			continue
		}
		elem := strings.Split(v, ",")
		if len(elem) != 6 {
			errRules = append(errRules, errRule{
				Lineno: i + 2,
				Raw:    v,
				Err:    fmt.Errorf("该行字段数量不足"),
			})
			continue
		}

		reg, err := regexp.Compile(elem[0])
		if err != nil {
			errRules = append(errRules, errRule{
				Lineno: i + 2,
				Raw:    v,
				Err:    err,
			})
			continue
		}
		rules = append(rules, rule{
			Pattern: reg,
			GuiseIP: elem[1],
			ReadIP:  elem[2],
			Dns:     elem[3],
			Mark:    elem[4],
			Black:   elem[5],
		})

	}
	f.Close()
	if len(errRules) != 0 {
		for _, v := range errRules {
			log.Printf("解析规则失败: 第%d行 [%s] 失败原因: %s", v.Lineno, v.Raw, v.Err)
		}
		return
	}

	log.Printf("启动监听 %v", flags.BindAddr)
	go func() {
		if err := serve(flags.BindAddr); err != nil {
			log.Fatal(err)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, os.Interrupt, os.Kill)
	<-sigCh
}

func serve(host string) error {
	addr, err := net.ResolveTCPAddr("tcp", host)
	if err != nil {
		return err
	}

	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return err
	}

	for {
		c, err := l.AcceptTCP()
		if err != nil {
			log.Printf("接收链接失败: %s", err)
			continue
		}

		go func() {
			defer c.Close()
			// 读取起源目标地址
			dest, err := GetOrigDst(c, false)
			if err != nil {
				log.Printf("从[%s]读取起源地址失败: %s, 关闭链接", c.RemoteAddr(), err)
				return
			}
			destAddr, destPort, err := net.SplitHostPort(dest.String())
			if err != nil {
				log.Printf("从起源地址[%s]解析IP与端口失败: %s, 关闭链接", dest, err)
				return
			}
			// read domain name
			var readDomain readDomainFunc
			switch destPort {
			case remoteHttpPort:
				readDomain = parseDomainHttp
			case remoteHttpsPort:
				readDomain = parseDomainHttps
			default:
				log.Printf("起源目标端口不是80或者443, 无法确定拆包结构")
				return
			}
			domain, header, err := readDomain(c)
			ipLink := false
			if err != nil {
				if header == nil {
					log.Printf("读取client hello或者HTTP HOST失败：%s", err)
					return
				}
				ipLink = true
			}

			remoteAddr := net.JoinHostPort(destAddr, destPort)
			addr, err := net.ResolveTCPAddr("tcp", remoteAddr)
			if err != nil {
				log.Printf("目标地址%s不是一个有效得地址, 关闭链接", remoteAddr)
				return
			}

			ctx, cancel := context.WithCancel(context.Background())
			dialer := &net.Dialer{
				Control: func(_, _ string, c syscall.RawConn) error {
					return c.Control(func(fd uintptr) {
						if err := setMark(int(fd), 100); err != nil {
							log.Printf("设置标记失败: %s", err)
							cancel()
							return
						}
					})
				},
			}

			rc, err := dialer.DialContext(ctx, "tcp", addr.String())
			if err != nil {
				log.Printf("链接目标地址失败 %s: %s", remoteAddr, err)
				return
			}
			defer rc.Close()

			switch ipLink {
			case true:
				log.Printf("转发 %s <-> %s <-> %s(%s), 该条未读取到域名",
					c.RemoteAddr(), rc.LocalAddr(), rc.RemoteAddr(), domain)
			case false:
				log.Printf("转发 %s <-> %s <-> %s(%s)",
					c.RemoteAddr(), rc.LocalAddr(), rc.RemoteAddr(), domain)
			}

			// 发送头部
			_, err = io.Copy(rc, bytes.NewReader(header))
			if err != nil && err != net.ErrClosed {
				log.Printf("转发%s握手出现错误: %v", domain, err)
			}
			if err := relay(rc.(*net.TCPConn), c); err != nil {
				log.Printf("转发%s出现错误: %v", domain, err)
			}
		}()
	}
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

func parseDomainHttp(r *net.TCPConn) (string, []byte, error) {
	header, err := readHeader(r)
	if err != nil {
		return "", nil, err
	}

	// read all header
	reg := regexp.MustCompile(`Host:.*\r\n`)
	domains := reg.FindAllString(string(header), -1)
	if domains == nil {
		return "", header, fmt.Errorf("not found Host field")
	}
	domain := strings.TrimRight(strings.Split(domains[0], ":")[1], "\r\n")
	domain = strings.TrimLeft(domain, " ")
	return domain, header, nil
}

func parseDomainHttps(r *net.TCPConn) (string, []byte, error) {
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
		return "", nil, err
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
		return "", header, fmt.Errorf("tls header: not enough data")
	}
	if int(header[0])&0x80 != 0 && int(header[2]) == 1 {
		return "", header, fmt.Errorf("tls header: SSL 2.0, does not support SNI")
	}
	if header[0] != TLSHANDSHAKECONTENTTYPE {
		return "", header, fmt.Errorf("tls header: tls content type not 0x16")
	}
	if header[1] < 3 {
		return "", header, fmt.Errorf("tls header: TLS major version < 3, does not support SNI")
	}
	recordLen := int(header[3])<<8 + int(header[4]) + TLSHEADERLEN
	if length < recordLen {
		return "", header, fmt.Errorf("tls header: not enough data2")
	}
	if header[TLSHEADERLEN] != TLSHANDSHAKETYPECLIENTHELLO {
		return "", header, fmt.Errorf("tls header: invalid handshake type")
	}

	pos += TLSHEADERLEN + FIXEDLENGTHRECORDS
	// skip session ID
	if pos+1 > length || pos+1+int(header[pos]) > length {
		return "", header, fmt.Errorf("tls header: not enough data3")
	}
	pos += 1 + int(header[pos])
	// skip cipher suites
	if pos+2 > length || (pos+2+(int(header[pos])<<8)+int(header[pos+1]) > length) {
		return "", header, fmt.Errorf("tls header: not enough data4")
	}
	pos += 2 + (int(header[pos]) << 8) + int(header[pos+1])
	// skip compression methods
	if pos+1 > length || pos+1+int(header[pos]) > length {
		return "", header, fmt.Errorf("tls header: not enough data5")
	}
	pos += 1 + int(header[pos])
	// skip extension length
	if pos+2 > length {
		return "", header, fmt.Errorf("tls header: not enough data6")
	}
	pos += 2

	// parse extension data
	for {
		if pos+4 > recordLen {
			return "", header, fmt.Errorf("tls header: buffer more than one record, SNI still not found")
		}
		if pos+4 > length {
			return "", header, fmt.Errorf("tls header: not enough data7")
		}
		extDataLen := (int(header[pos+2]) << 8) + int(header[pos+3])
		if int(header[pos]) == 0 && int(header[pos+1]) == 0 {
			// server_name extension type
			pos += 4
			if pos+5 > length {
				return "", header, fmt.Errorf("tls header: not server_name list header")
			}
			serverNameLen := (int(header[pos+3]) << 8) + int(header[pos+4])
			if pos+5+serverNameLen > length {
				return "", header, fmt.Errorf("tls header: not server_name list header")
			}
			// return server_name
			if serverNameLen+1 > DOMAINLEN {
				return "", header, fmt.Errorf("tls header: The domain name is too long")
			}
			serverName := header[pos+5 : pos+5+serverNameLen]
			return string(serverName), header, nil
		} else {
			// skip
			pos += 4 + extDataLen
		}
	}
}
