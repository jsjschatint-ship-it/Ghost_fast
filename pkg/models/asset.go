package models

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Asset 表示一条资产记录（与 Python 版保持一致）
type Asset struct {
	// 核心定位
	IP       string `json:"ip,omitempty" yaml:"ip,omitempty"`
	Port     int    `json:"port,omitempty" yaml:"port,omitempty"`
	Protocol string `json:"protocol,omitempty" yaml:"protocol,omitempty"` // http/https/tcp/udp...
	Domain   string `json:"domain,omitempty" yaml:"domain,omitempty"`     // 主域/子域
	Host     string `json:"host,omitempty" yaml:"host,omitempty"`         // 完整 host（可能含端口或 hostname）
	URL      string `json:"url,omitempty" yaml:"url,omitempty"`           // 链接

	// 服务/指纹
	Service  string   `json:"service,omitempty" yaml:"service,omitempty"`   // 服务名 (nginx/ssh/mysql...)
	Title    string   `json:"title,omitempty" yaml:"title,omitempty"`       // 网页标题
	Server   string   `json:"server,omitempty" yaml:"server,omitempty"`     // Server 头
	Products []string `json:"products,omitempty" yaml:"products,omitempty"` // 产品/组件
	OS       string   `json:"os,omitempty" yaml:"os,omitempty"`             // 操作系统

	// 网络/地理
	Country  string `json:"country,omitempty" yaml:"country,omitempty"`
	Province string `json:"province,omitempty" yaml:"province,omitempty"`
	City     string `json:"city,omitempty" yaml:"city,omitempty"`
	ASN      string `json:"asn,omitempty" yaml:"asn,omitempty"`
	Org      string `json:"org,omitempty" yaml:"org,omitempty"`
	ISP      string `json:"isp,omitempty" yaml:"isp,omitempty"`

	// 证书/指纹哈希
	CertSubject string   `json:"cert_subject,omitempty" yaml:"cert_subject,omitempty"`
	CertIssuer  string   `json:"cert_issuer,omitempty" yaml:"cert_issuer,omitempty"`
	CertDomains []string `json:"cert_domains,omitempty" yaml:"cert_domains,omitempty"`
	JARM        string   `json:"jarm,omitempty" yaml:"jarm,omitempty"`
	JA3S        string   `json:"ja3s,omitempty" yaml:"ja3s,omitempty"`
	FaviconHash string   `json:"favicon_hash,omitempty" yaml:"favicon_hash,omitempty"`
	ICP         string   `json:"icp,omitempty" yaml:"icp,omitempty"` // ICP 备案号

	// 元数据
	Source     string            `json:"source,omitempty" yaml:"source,omitempty"` // fofa/quake/hunter/zoomeye/shodan/ctlog/fofa_xlsx...
	UpdateTime string            `json:"update_time,omitempty" yaml:"update_time,omitempty"`
	Raw        map[string]string `json:"raw,omitempty" yaml:"raw,omitempty"`
	Tags       []string          `json:"tags,omitempty" yaml:"tags,omitempty"`
	Created    time.Time         `json:"created,omitempty" yaml:"created,omitempty"`
}

// NewAsset 创建新资产
func NewAsset() *Asset {
	return &Asset{
		Created: time.Now().UTC(),
	}
}

// WithDomain 设置域名
func (a *Asset) WithDomain(domain string) *Asset {
	a.Domain = domain
	return a
}

// WithHost 设置主机
func (a *Asset) WithHost(host string) *Asset {
	a.Host = host
	return a
}

// WithURL 设置 URL
func (a *Asset) WithURL(url string) *Asset {
	a.URL = url
	return a
}

// WithIP 设置 IP
func (a *Asset) WithIP(ip string) *Asset {
	a.IP = ip
	return a
}

// WithTitle 设置标题
func (a *Asset) WithTitle(title string) *Asset {
	a.Title = title
	return a
}

// WithSource 设置来源
func (a *Asset) WithSource(source string) *Asset {
	a.Source = source
	return a
}

// WithTags 设置标签
func (a *Asset) WithTags(tags ...string) *Asset {
	a.Tags = append(a.Tags, tags...)
	return a
}

// WithRaw 设置原始数据
func (a *Asset) WithRaw(key, value string) *Asset {
	if a.Raw == nil {
		a.Raw = make(map[string]string)
	}
	a.Raw[key] = value
	return a
}

// WithPort 设置端口
func (a *Asset) WithPort(port int) *Asset { a.Port = port; return a }

// WithProtocol 设置协议
func (a *Asset) WithProtocol(p string) *Asset { a.Protocol = p; return a }

// WithService 设置服务
func (a *Asset) WithService(s string) *Asset { a.Service = s; return a }

// WithServer 设置 Server 头
func (a *Asset) WithServer(s string) *Asset { a.Server = s; return a }

// WithCountry 设置国家
func (a *Asset) WithCountry(c string) *Asset { a.Country = c; return a }

// WithProvince 设置省份
func (a *Asset) WithProvince(p string) *Asset { a.Province = p; return a }

// WithCity 设置城市
func (a *Asset) WithCity(c string) *Asset { a.City = c; return a }

// WithASN 设置 ASN
func (a *Asset) WithASN(asn string) *Asset { a.ASN = asn; return a }

// WithOrg 设置组织
func (a *Asset) WithOrg(o string) *Asset { a.Org = o; return a }

// WithISP 设置 ISP
func (a *Asset) WithISP(i string) *Asset { a.ISP = i; return a }

// WithICP 设置 ICP 备案号
func (a *Asset) WithICP(i string) *Asset { a.ICP = i; return a }

// WithOS 设置操作系统
func (a *Asset) WithOS(o string) *Asset { a.OS = o; return a }

// WithProduct 添加产品/组件
func (a *Asset) WithProduct(p string) *Asset {
	if p != "" {
		a.Products = append(a.Products, p)
	}
	return a
}

// WithCertSubject 设置证书 Subject
func (a *Asset) WithCertSubject(s string) *Asset { a.CertSubject = s; return a }

// WithCertIssuer 设置证书 Issuer
func (a *Asset) WithCertIssuer(s string) *Asset { a.CertIssuer = s; return a }

// WithCertDomains 添加证书域名
func (a *Asset) WithCertDomains(d ...string) *Asset {
	a.CertDomains = append(a.CertDomains, d...)
	return a
}

// WithJARM 设置 JARM 指纹
func (a *Asset) WithJARM(j string) *Asset { a.JARM = j; return a }

// WithFaviconHash 设置 favicon hash
func (a *Asset) WithFaviconHash(h string) *Asset { a.FaviconHash = h; return a }

// WithUpdateTime 设置更新时间字符串
func (a *Asset) WithUpdateTime(t string) *Asset { a.UpdateTime = t; return a }

// cleanHost 规范化 host 字段（去掉 scheme、路径、查询串、末尾端口）
func cleanHost(s string) string {
	if s == "" {
		return ""
	}
	schemeRE := regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+\-.]*://`)
	s = schemeRE.ReplaceAllString(s, "")
	for _, sep := range []string{"/", "?", "#"} {
		if idx := strings.Index(s, sep); idx != -1 {
			s = s[:idx]
		}
	}
	return strings.ToLower(s)
}

// Normalize 规范化字段（类似 __post_init__）
func (a *Asset) Normalize() {
	if a.Host != "" {
		a.Host = cleanHost(a.Host)
	}
	if a.Domain != "" {
		a.Domain = cleanHost(a.Domain)
	}
	// 如果 host 含了端口又没 port 字段，把 port 拆出来
	if a.Host != "" && strings.Contains(a.Host, ":") && a.Port == 0 {
		parts := strings.Split(a.Host, ":")
		if len(parts) == 2 {
			if p := parts[1]; p != "" {
				if port, err := strconv.Atoi(p); err == nil {
					a.Host = parts[0]
					a.Port = port
				}
			}
		}
	}
}

// Key 跨源去重主键（与 Python 版保持一致）
func (a *Asset) Key() string {
	host := strings.ToLower(a.Host)
	if host == "" {
		host = strings.ToLower(a.Domain)
	}
	port := a.Port
	// Web 资产：把 80/443 折叠到统一的 :web
	proto := strings.ToLower(a.Protocol)
	if proto == "" {
		proto = strings.ToLower(a.Service)
	}
	isWeb := (port == 80 || port == 443 || port == 8080 || port == 8443) ||
		proto == "http" || proto == "https" ||
		strings.Contains(proto, "http")
	if isWeb && host != "" && (port == 80 || port == 443) {
		return host + ":web"
	}
	if a.IP != "" && port != 0 {
		return a.IP + ":" + strconv.Itoa(port)
	}
	if host != "" && port != 0 {
		return host + ":" + strconv.Itoa(port)
	}
	if host != "" {
		return host
	}
	if a.URL != "" {
		return strings.ToLower(a.URL)
	}
	if a.IP != "" {
		return a.IP
	}
	return ""
}

// ToDict 转为字典（与 Python 版 to_dict 一致）
func (a *Asset) ToDict() map[string]any {
	d := map[string]any{
		"ip":           a.IP,
		"port":         a.Port,
		"protocol":     a.Protocol,
		"domain":       a.Domain,
		"host":         a.Host,
		"url":          a.URL,
		"service":      a.Service,
		"title":        a.Title,
		"server":       a.Server,
		"products":     strings.Join(a.Products, ","),
		"os":           a.OS,
		"country":      a.Country,
		"province":     a.Province,
		"city":         a.City,
		"asn":          a.ASN,
		"org":          a.Org,
		"isp":          a.ISP,
		"cert_subject": a.CertSubject,
		"cert_issuer":  a.CertIssuer,
		"cert_domains": strings.Join(a.CertDomains, ","),
		"jarm":         a.JARM,
		"ja3s":         a.JA3S,
		"favicon_hash": a.FaviconHash,
		"icp":          a.ICP,
		"source":       a.Source,
		"update_time":  a.UpdateTime,
		"tags":         strings.Join(a.Tags, ","),
		"created":      a.Created.Format(time.RFC3339),
	}
	// 移除空字段
	for k, v := range d {
		if v == "" || v == 0 {
			delete(d, k)
		}
	}
	return d
}
