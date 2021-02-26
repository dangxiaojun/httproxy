package main

import (
	"bytes"
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
	"syscall"
	"time"
)

const (
	remoteHttpPort  string = "80"
	remoteHttpsPort string = "443"
)

func main() {

	var flags struct {
		BindAddr   string
		HttpPort   string
		TlsPort    string
		AccessFile string
		WhiteMode  bool
		BlackMode  bool
		Help       bool
	}
	var domains []*regexp.Regexp
	var accessHandle func(string) bool

	flag.StringVar(&flags.BindAddr, "h", "0.0.0.0", "bind address")
	flag.StringVar(&flags.HttpPort, "p", "80", "bind http port")
	flag.StringVar(&flags.TlsPort, "t", "443", "bind https port")
	flag.StringVar(&flags.AccessFile, "f", "", "access control rule file")
	flag.BoolVar(&flags.WhiteMode, "w", false, "run as whitelist mode")
	flag.BoolVar(&flags.BlackMode, "b", false, "run as blacklist mode")
	flag.BoolVar(&flags.Help, "help", false, "help")
	flag.Parse()

	log.SetPrefix("TRACE ")
	log.SetOutput(os.Stdout)
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	if flags.Help {
		flag.Usage()
		return
	}

	if flags.WhiteMode && flags.BlackMode {
		log.Fatalf("cannot running with blacklist mode and whitelist mode, just one")
	}
	if flags.WhiteMode || flags.BlackMode {
		if flags.AccessFile == "" {
			log.Fatalf("running with blacklist mode or whitelist mode, must need access list file")
		}
		// read domain list
		f, err := os.OpenFile(flags.AccessFile, os.O_RDONLY, 0600)
		if err != nil {
			log.Fatalf("connot read access list file: %s", err)
		}
		accessBytes, err := ioutil.ReadAll(f)
		if err != nil && err != io.EOF {
			log.Fatalf("connot read access list file: %s", err)
		}
		domainsList := strings.Split(string(accessBytes), "\n")
		var errDomain []struct {
			Lineno  int
			Pattern string
			Err     error
		}
		for i, v := range domainsList {
			if reg, err := regexp.Compile(v); err != nil {
				errDomain = append(errDomain, struct {
					Lineno  int
					Pattern string
					Err     error
				}{Lineno: i + 1, Pattern: v, Err: err})
			} else {
				domains = append(domains, reg)
			}
		}
		f.Close()
		if len(errDomain) != 0 {
			for _, v := range errDomain {
				log.Printf("parse pattern line %d [%s] failed: %s", v.Lineno, v.Pattern, v.Err)
			}
			log.Fatalf("parse pattern failed")
		}
		if flags.WhiteMode {
			accessHandle = access(domains, true)
		} else {
			accessHandle = access(domains, false)
		}
	} else {
		accessHandle = nil
	}

	// http
	if err := serve(flags.BindAddr, flags.HttpPort, false, parseDomainHttp, accessHandle); err != nil {
		log.Fatal(err)
	}

	// https
	if err := serve(flags.BindAddr, flags.TlsPort, true, parseDomainHttps, accessHandle); err != nil {
		log.Fatal(err)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, os.Interrupt, os.Kill)
	<-sigCh
}

func access(domainsRegexp []*regexp.Regexp, mode bool) func(string) bool {
	return func(s string) bool {
		found := false
		for _, v := range domainsRegexp {
			if matched := v.MatchString(s); matched {
				found = true
				break
			}
		}
		return found == mode
	}
}

func serve(host, port string, tls bool, readDomain func(conn net.TCPConn) (string, []byte, error), isAccess func(string) bool) error {
	addr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(host, port))
	if err != nil {
		log.Printf("not a valid bind address: %s", addr)
		return err
	}

	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return err
	}

	log.Printf("listening on %s", net.JoinHostPort(host, port))
	go func() {
		for {
			c, err := l.AcceptTCP()
			if err != nil {
				log.Printf("failed to accept: %s", err)
				continue
			}

			go func() {
				defer c.Close()
				// read domain name
				domain, header, err := readDomain(*c)
				if err != nil {
					log.Printf("cannot parse domain from [%s]: %s, close connect", c.RemoteAddr(), err)
					return
				}

				// acl
				if isAccess != nil {
					if !isAccess(domain) {
						log.Printf("disable black domain [%s], close connect", domain)
						return
					}
				}

				remoteAddr := net.JoinHostPort(domain, func() string {
					if tls {
						return remoteHttpsPort
					}
					return remoteHttpPort
				}())
				addr, err := net.ResolveTCPAddr("tcp", remoteAddr)
				if err != nil {
					log.Printf("not a valid address: %s, close connect", remoteAddr)
					return
				}
				rc, err := net.DialTCP("tcp", nil, addr)
				if err != nil {
					log.Printf("failed to connect to target %s: %s", remoteAddr, err)
					return
				}
				defer rc.Close()

				setMark(rc, 100)

				log.Printf("proxy %s <-> %s <-> %s <-> %s(%s)",
					c.RemoteAddr(), c.LocalAddr(), rc.LocalAddr(), domain, rc.RemoteAddr())

				go func() {
					defer rc.Close()
					_, err = io.Copy(rc, bytes.NewReader(header))
					if err != nil && !errors.Is(err, net.ErrClosed) {
						log.Printf("send header error: %s, %s", domain, err)
						return
					}
					_, err := io.CopyBuffer(rc, c, make([]byte, 2048))
					if err != nil && !errors.Is(err, net.ErrClosed) {
						log.Printf("proxy error: %s: %s", domain, err)
					}
				}()
				_, err = io.CopyBuffer(c, rc, make([]byte, 2048))
				rc.SetDeadline(time.Now()) // wake up the another goroutine blocking on rc
				c.SetDeadline(time.Now())  // wake up the another goroutine blocking on c
				if err != nil && !errors.Is(err, net.ErrClosed) {
					log.Printf("proxy error: %s: %s", domain, err)
				}
			}()
		}
	}()

	return nil
}

func readHeader(r net.TCPConn) ([]byte, error) {
	buf := make([]byte, 16384)
	n, err := r.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("read header failed: %s", err)
	}
	return buf[:n], nil
}

func parseDomainHttp(r net.TCPConn) (string, []byte, error) {
	header, err := readHeader(r)
	if err != nil {
		return "", nil, err
	}

	// read all header
	reg := regexp.MustCompile(`Host:.*\r\n`)
	domains := reg.FindAllString(string(header), -1)
	if domains == nil {
		return "", nil, fmt.Errorf("not found Host field")
	}
	domain := strings.TrimRight(strings.Split(domains[0], ":")[1], "\r\n")
	domain = strings.TrimLeft(domain, " ")
	return domain, header, nil
}

func parseDomainHttps(r net.TCPConn) (string, []byte, error) {
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
		return "", nil, fmt.Errorf("tls header: not enough data")
	}
	if int(header[0])&0x80 != 0 && int(header[2]) == 1 {
		return "", nil, fmt.Errorf("tls header: SSL 2.0, does not support SNI")
	}
	if header[0] != TLSHANDSHAKECONTENTTYPE {
		return "", nil, fmt.Errorf("tls header: tls content type not 0x16")
	}
	if header[1] < 3 {
		return "", nil, fmt.Errorf("tls header: TLS major version < 3, does not support SNI")
	}
	recordLen := int(header[3])<<8 + int(header[4]) + TLSHEADERLEN
	if length < recordLen {
		return "", nil, fmt.Errorf("tls header: not enough data2")
	}
	if header[TLSHEADERLEN] != TLSHANDSHAKETYPECLIENTHELLO {
		return "", nil, fmt.Errorf("tls header: invalid handshake type")
	}

	pos += TLSHEADERLEN + FIXEDLENGTHRECORDS
	// skip session ID
	if pos+1 > length || pos+1+int(header[pos]) > length {
		return "", nil, fmt.Errorf("tls header: not enough data3")
	}
	pos += 1 + int(header[pos])
	// skip cipher suites
	if pos+2 > length || (pos+2+(int(header[pos])<<8)+int(header[pos+1]) > length) {
		return "", nil, fmt.Errorf("tls header: not enough data4")
	}
	pos += 2 + (int(header[pos]) << 8) + int(header[pos+1])
	// skip compression methods
	if pos+1 > length || pos+1+int(header[pos]) > length {
		return "", nil, fmt.Errorf("tls header: not enough data5")
	}
	pos += 1 + int(header[pos])
	// skip extension length
	if pos+2 > length {
		return "", nil, fmt.Errorf("tls header: not enough data6")
	}
	pos += 2

	// parse extension data
	for {
		if pos+4 > recordLen {
			return "", nil, fmt.Errorf("tls header: buffer more than one record, SNI still not found")
		}
		if pos+4 > length {
			return "", nil, fmt.Errorf("tls header: not enough data7")
		}
		extDataLen := (int(header[pos+2]) << 8) + int(header[pos+3])
		if int(header[pos]) == 0 && int(header[pos+1]) == 0 {
			// server_name extension type
			pos += 4
			if pos+5 > length {
				return "", nil, fmt.Errorf("tls header: not server_name list header")
			}
			serverNameLen := (int(header[pos+3]) << 8) + int(header[pos+4])
			if pos+5+serverNameLen > length {
				return "", nil, fmt.Errorf("tls header: not server_name list header")
			}
			// return server_name
			if serverNameLen+1 > DOMAINLEN {
				return "", nil, fmt.Errorf("tls header: The domain name is too long")
			}
			serverName := header[pos+5 : pos+5+serverNameLen]
			return string(serverName), header, nil
		} else {
			// skip
			pos += 4 + extDataLen
		}
	}
}
