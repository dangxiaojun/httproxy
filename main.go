package main

import (
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
	"time"
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
		for _, v := range domainsList {
			if reg, err := regexp.Compile(v); err != nil {
				log.Fatalf("parse pattern [%s] failed: %s", v, err)
			} else {
				domains = append(domains, reg)
			}
		}
		f.Close()
		if flags.WhiteMode {
			accessHandle = access(domains, true)
		} else {
			accessHandle = access(domains, false)
		}
	} else {
		accessHandle = nil
	}

	// http
	if err := serve(flags.BindAddr, flags.HttpPort, parseDomainHttp, accessHandle); err != nil {
		log.Fatal(err)
	}

	// https
	if err := serve(flags.BindAddr, flags.TlsPort, parseDomainHttps, accessHandle); err != nil {
		log.Fatal(err)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, os.Interrupt, os.Kill)
	<-sigCh
	log.Fatalf("Exit!!!")
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

func serve(host, port string, readDomain func(net.Conn) (string, []byte, error), isAccess func(string) bool) error {
	l, err := net.Listen("tcp", net.JoinHostPort(host, port))
	if err != nil {
		return err
	}

	log.Printf("listening on %s", net.JoinHostPort(host, port))
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				log.Printf("failed to accept: %s", err)
				continue
			}

			go func() {
				defer c.Close()
				// read domain name
				domain, header, err := readDomain(c)
				if err != nil {
					log.Printf("cannot parse domain from [%s]: %s, close connect", c.RemoteAddr(), err)
					return
				}
				remoteAddr := net.JoinHostPort(domain, port)

				// acl
				if isAccess != nil {
					if !isAccess(domain) {
						log.Printf("disable black domain [%s], close connect", domain)
						return
					}
				}

				rc, err := net.DialTimeout("tcp", remoteAddr, time.Second*2)
				if err != nil {
					log.Printf("failed to connect to target %s: %s", remoteAddr, err)
					return
				}
				defer rc.Close()

				log.Printf("proxy [%s <-> %s <-> %s <-> %s(%s)]",
					c.RemoteAddr(), c.LocalAddr(), rc.LocalAddr(), domain, rc.RemoteAddr())
				_, _ = rc.Write(header)
				if err = relay(c, rc); err != nil {
					log.Printf("relay error: [%s <-> %s <-> %s <-> %s(%s)]: %s",
						c.RemoteAddr(), c.LocalAddr(), rc.LocalAddr(), domain, rc.RemoteAddr(), err)
				}
			}()
		}
	}()

	return nil
}

func readHeader(r net.Conn) ([]byte, error) {
	buf := make([]byte, 16384)
	for {
		r.SetReadDeadline(time.Now().Add(time.Second * 1))
		n, err := r.Read(buf)
		if err != nil {
			return nil, err
		}
		return buf[:n], err
	}
}

func parseDomainHttp(r net.Conn) (string, []byte, error) {
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

func parseDomainHttps(r net.Conn) (string, []byte, error) {
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
	// TODO parse https header

	return "", header, nil
}

func relay(left, right net.Conn) error {
	var err, err1 error
	var wg sync.WaitGroup
	var wait = 5 * time.Second
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err1 = io.Copy(right, left)
		right.SetReadDeadline(time.Now().Add(wait)) // unblock read on right
	}()
	_, err = io.Copy(left, right)
	left.SetReadDeadline(time.Now().Add(wait)) // unblock read on left
	wg.Wait()
	if err1 != nil && !errors.Is(err1, os.ErrDeadlineExceeded) { // requires Go 1.15+
		return err1
	}
	if err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
		return err
	}
	return nil
}
