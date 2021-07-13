package acl

import (
	"fmt"
	"io/ioutil"
	"log"
	"regexp"
	"strconv"
	"strings"
)

const (
	RedirectMark = 0x32 // 60
	DnsMark      = 0x28 // 50
	WhiteMark    = 0x1e // 40
	DefaultMark  = 0x14 // 20
)

// Report 域名控制结果
type Report struct {
	RedirectAddr string // 多出口与指定出口的最终目标地址结果
	ReDns        string // 该值指定需要使用使用DNS重解析地址后发起链接
	Mark         int    // 使用该mark值
	Black        bool   // 是否位于黑名单列表中
}

type (
	rule struct {
		Lineno  int
		Pattern *regexp.Regexp
		MaskIP  string
		RealIP  string
		Dns     string
		Mark    int
		Black   bool
		Raw     string
	}
	errRule struct {
		Lineno int
		Raw    string
		Err    error
	}
)

var aclRules []rule
var mapRules []rule
var ipPattern, _ = regexp.Compile(`(\d{1,3}\.){3}\d{1,3}`)
var dnsPattern, _ = regexp.Compile(`(\d{1,3}\.){3}\d{1,3}:\d+`)

func Parse(f string) error {
	rBuf, err := ioutil.ReadFile(f)
	if err != nil {
		return err
	}

	var rules []rule
	var mapping []rule
	var errRules []errRule
	for i, v := range strings.Split(strings.ReplaceAll(string(rBuf), "\r", ""), "\n") {
		if v == "" || strings.HasPrefix(v, "#") {
			continue
		}
		lineno := i + 1
		elem := strings.Split(v, ",")
		if len(elem) != 6 {
			errRules = append(errRules, errRule{
				Lineno: lineno,
				Raw:    v,
				Err:    fmt.Errorf("该行字段数量不足, 请检查配置"),
			})
			continue
		}

		reg, err := regexp.Compile(elem[0])
		if err != nil {
			errRules = append(errRules, errRule{
				Lineno: lineno,
				Raw:    v,
				Err:    err,
			})
			continue
		}
		// 解析各个字段是否符合规则
		maskIP := elem[1]
		realIP := elem[2]
		dns := elem[3]
		mark := 0
		black := elem[5] != "" && elem[5] != "0" // 非0和空，即为启用黑名单

		if elem[4] != "" && elem[4] != "0" {
			if mark, err = strconv.Atoi(elem[4]); err != nil {
				errRules = append(errRules, errRule{
					Lineno: lineno,
					Raw:    v,
					Err:    fmt.Errorf("mark标记字段格式错误: %v", err),
				})
				continue
			}
		}

		if maskIP != "" && !ipPattern.MatchString(maskIP) {
			errRules = append(errRules, errRule{
				Lineno: lineno,
				Raw:    v,
				Err:    fmt.Errorf("伪装IP字段不符合IP地址规则"),
			})
			continue
		}
		if realIP != "" && !ipPattern.MatchString(realIP) {
			errRules = append(errRules, errRule{
				Lineno: lineno,
				Raw:    v,
				Err:    fmt.Errorf("转发目标IP字段不符合IP地址规则"),
			})
			continue
		}
		if dns != "" && !(ipPattern.MatchString(dns) || dnsPattern.MatchString(dns)) {
			errRules = append(errRules, errRule{
				Lineno: lineno,
				Raw:    v,
				Err:    fmt.Errorf("重解析dns字段不符合IP地址(ip[:port])规则"),
			})
			continue
		}
		if dns != "" && !strings.Contains(dns, ":") {
			dns = dns + ":53"
		}

		r := rule{
			Lineno:  lineno,
			Pattern: reg,
			MaskIP:  maskIP,
			RealIP:  realIP,
			Dns:     dns,
			Mark:    mark,
			Black:   black,
			Raw:     v,
		}
		if r.MaskIP == "" {
			rules = append(rules, r)
		} else {
			mapping = append(mapping, r)
		}
	}

	if len(errRules) != 0 {
		for _, v := range errRules {
			log.Printf("解析规则失败: 第%d行 [%s] 失败原因: %s", v.Lineno, v.Raw, v.Err)
		}
		return fmt.Errorf("解析配置文件出错")
	}

	aclRules = rules
	mapRules = mapping
	return nil
}

func GetReport(domain, origDestAddr string) Report {
	if domain == "" {
		return Report{
			RedirectAddr: origDestAddr,
			ReDns:        "",
			Mark:         DefaultMark,
			Black:        false,
		}
	}

	// map多出口映射配置，存在一个域名有多行情况，所以单独抽出来进行全部匹配
	for _, v := range mapRules {
		if v.Pattern.MatchString(domain) {
			if v.MaskIP == origDestAddr {
				return Report{
					RedirectAddr: v.RealIP,
					ReDns:        "",
					Mark:         RedirectMark,
					Black:        false,
				}
			}
		}
	}

	// 剩下的都是单行域名，按优先级匹配
	for _, v := range aclRules {
		if v.Pattern.MatchString(domain) {
			r := Report{
				RedirectAddr: v.RealIP,
				ReDns:        v.Dns,
				Mark:         RedirectMark,
				Black:        v.Black,
			}
			if v.Dns != "" {
				r.Mark = DnsMark
			}
			if v.RealIP == "" {
				r.Mark = WhiteMark
			}
			return r
		}
	}

	return Report{
		RedirectAddr: origDestAddr,
		ReDns:        "",
		Mark:         DefaultMark,
		Black:        false,
	}
}

// Test 域名测试
func Test(domain, origDestAddr string) {
	count := 1
	log.Printf("域名[%s]将按照以下顺序命中", domain)

	for _, v := range mapRules {
		if v.Pattern.MatchString(domain) {
			if v.MaskIP == origDestAddr {
				log.Printf("[%3d] 命中第[%d]行: %s", count, v.Lineno, v.Raw)
				log.Printf("      命中多出口IP解析, 将使用标记[0x%x]转发本条域名链接至[%s]", RedirectMark, v.RealIP)
				count++
			}
		}
	}

	// 剩下的都是单行域名，按优先级匹配
	for _, v := range aclRules {
		if v.Pattern.MatchString(domain) {
			log.Printf("[%3d] 命中第[%d]行: %s", count, v.Lineno, v.Raw)
			if v.Black {
				log.Printf("      命中黑名单域名, 本条域名链接将被阻断")
			} else if v.Dns != "" {
				log.Printf("      命中DNS重新解析域名, 本条域名将被发往[%s]进行解析，然后使用标记[0x%x]链接到解析结果", v.Dns, DnsMark)
			} else if v.RealIP == "" {
				log.Printf("      命中纯标记白名单域名, 将使用标记[0x%x]转发本条域名链接至原始地址[%s]", WhiteMark, origDestAddr)
			}
			count++
		}
	}

	log.Printf("[%3d] 未命中任何规则条目, 将使用默认标记[0x%x]转发本条域名链接至原始地址[%s]", count, DefaultMark, origDestAddr)
}
