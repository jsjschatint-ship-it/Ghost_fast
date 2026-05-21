// Package vendor 厂商 → 客户反查（downstream pivot）。
// 找出所有"使用了 vendor 公司开发的系统"的站点（与 pivots 寻找兄弟资产相反）。
package vendor

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/wgpsec/ENScan/pkg/models"
	"github.com/wgpsec/ENScan/pkg/source"
	"github.com/wgpsec/ENScan/pkg/source/supply/internal/fofahelper"
)

var (
	rePowered      = regexp.MustCompile(`(?i)(?:Powered\s*by|技术支持[:：]?|Powered-By[:：]?|Copyright\s*[©Cc]\s*\d{4})\s*["'<>]*([^"'<>\n\r,，。]{3,60})`)
	reProductTitle = regexp.MustCompile(`(?i)<title[^>]*>\s*([^<]{4,80}?(?:管理系统|平台|系统|后台|OA|CRM|ERP|商城|门户|登录|Login))[^<]*</title>`)
	reServer       = regexp.MustCompile(`(?i)Server:\s*([^\r\n]+)`)
	reXPoweredBy   = regexp.MustCompile(`(?i)X-Powered-By:\s*([^\r\n]+)`)
	reUsefulCheck  = regexp.MustCompile(`[\p{Han}]{2,}|[A-Za-z]{4,}`)

	genericBlacklist = map[string]bool{
		"管理系统": true, "登录": true, "后台管理": true, "用户登录": true,
		"首页": true, "管理平台": true, "系统": true, "powered by": true,
		"copyright": true, "all rights reserved": true, "login": true, "admin": true,
		"welcome": true, "index": true, "home": true, "version": true,
		"服务": true, "平台": true, "门户": true,
	}

	commonServerBlacklist = map[string]bool{
		"nginx": true, "apache": true, "iis": true, "microsoft-iis": true,
		"openresty": true, "tengine": true, "lighttpd": true, "cloudflare": true,
	}
)

// Pivot 类型 → FOFA 字段
var pivotToField = map[string]string{
	"body_keywords":  "body",
	"title_keywords": "title",
	"server_headers": "header",
	"banner_strings": "banner",
}

// Fingerprints 厂商产品指纹集合
type Fingerprints struct {
	BodyKeywords  []string `json:"body_keywords"`
	TitleKeywords []string `json:"title_keywords"`
	ServerHeaders []string `json:"server_headers"`
	BannerStrings []string `json:"banner_strings"`
}

// Vendor 数据源
type Vendor struct {
	*source.BaseSource
	fofa *fofahelper.Client
}

// New 创建
func New() *Vendor {
	return &Vendor{
		BaseSource: source.NewBaseSource("supply_vendor"),
		fofa:       fofahelper.New(""),
	}
}

// Accepts 接受的输入类型
func (v *Vendor) Accepts() []string { return []string{"domain"} }

// NeedsKey 是否需要 API Key
func (v *Vendor) NeedsKey() bool { return true }

// SetConfig 配置
func (v *Vendor) SetConfig(cfg map[string]any) error {
	_ = v.BaseSource.SetConfig(cfg)
	if k, ok := cfg["fofa_key"].(string); ok && k != "" {
		v.fofa.Key = k
	} else if k, ok := cfg["key"].(string); ok && k != "" {
		v.fofa.Key = k
	}
	if e, ok := cfg["fofa_email"].(string); ok {
		v.fofa.Email = e
	}
	if p, ok := cfg["proxy"].(string); ok && p != "" {
		v.fofa.Proxy = p
	}
	if t, ok := cfg["timeout"].(int); ok && t > 0 {
		v.fofa.Timeout = time.Duration(t) * time.Second
	}
	return nil
}

// SetKey 透传 FOFA key
func (v *Vendor) SetKey(k string) {
	v.BaseSource.SetKey(k)
	v.fofa.Key = k
}

// Search 执行搜索
func (v *Vendor) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	cfg := &source.SearchConfig{MaxAssets: 500}
	for _, opt := range opts {
		opt(cfg)
	}
	domain := strings.TrimSpace(target)
	if domain == "" {
		return nil, nil
	}
	if v.fofa.Key == "" {
		return nil, fmt.Errorf("supply_vendor needs fofa_key")
	}
	maxPerFP := cfg.MaxAssets
	if maxPerFP <= 0 {
		maxPerFP = 500
	}

	fps := v.ExtractVendorFingerprints(ctx, domain, 30)
	const maxFPsPerType = 3
	vendorBrand := strings.ToLower(strings.SplitN(domain, ".", 2)[0])

	var all []*models.Asset
	for ptype, field := range pivotToField {
		var values []string
		switch ptype {
		case "body_keywords":
			values = fps.BodyKeywords
		case "title_keywords":
			values = fps.TitleKeywords
		case "server_headers":
			values = fps.ServerHeaders
		case "banner_strings":
			values = fps.BannerStrings
		}
		if len(values) > maxFPsPerType {
			values = values[:maxFPsPerType]
		}
		for _, val := range values {
			rs, err := v.fofa.SearchPaginated(ctx, fmt.Sprintf(`%s="%s"`, field, val), "host,link,domain,ip,port,title", maxPerFP)
			if err != nil {
				continue
			}
			tag := "customer-" + ptype
			for _, r := range rs {
				host, ip, port, title, dom, urlStr := fofahelper.RowToAssetFields(r)
				blob := strings.ToLower(host + " " + dom + " " + urlStr)
				if domain != "" && strings.Contains(blob, strings.ToLower(domain)) {
					continue
				}
				a := models.NewAsset().
					WithHost(host).WithIP(ip).WithPort(port).
					WithTitle(title).WithDomain(dom).WithURL(urlStr).
					WithSource("fofa-customer").
					WithTags(tag, "vendor:"+vendorBrand)
				a.Normalize()
				all = append(all, a)
			}
		}
	}
	return all, nil
}

// ExtractVendorFingerprints 提取 vendor 产品指纹
func (v *Vendor) ExtractVendorFingerprints(ctx context.Context, vendorDomain string, sample int) Fingerprints {
	bodyKW := map[string]bool{}
	titleKW := map[string]bool{}
	servers := map[string]bool{}
	banners := map[string]bool{}

	queries := []string{
		fmt.Sprintf(`host="%s"`, vendorDomain),
		fmt.Sprintf(`host="www.%s"`, vendorDomain),
		fmt.Sprintf(`domain="%s"`, vendorDomain),
	}
	var rows []fofahelper.Row
	for _, q := range queries {
		r, _ := v.fofa.Search(ctx, q, "host,title,header,banner,body", sample)
		rows = append(rows, r...)
		if len(rows) >= sample {
			break
		}
	}

	vendorBrand := strings.ToLower(strings.SplitN(vendorDomain, ".", 2)[0])

	for _, r := range rows {
		title := strings.TrimSpace(r["title"])
		header := r["header"]
		banner := r["banner"]
		body := r["body"]

		// 1) body / banner 中的版权/技术支持
		for _, src := range []string{body, banner} {
			for _, m := range rePowered.FindAllStringSubmatch(src, -1) {
				s := strings.TrimRight(strings.TrimSpace(m[1]), ".,，。 ")
				if isUsefulFP(s) {
					bodyKW[s] = true
				}
			}
		}
		// 2) title 中的产品名
		for _, m := range reProductTitle.FindAllStringSubmatch(body, -1) {
			s := strings.TrimSpace(m[1])
			if isUsefulFP(s) {
				titleKW[s] = true
			}
		}
		if title != "" && strings.Contains(strings.ToLower(title), vendorBrand) && isUsefulFP(title) {
			titleKW[title] = true
		}
		// 3) Server header
		for _, m := range reServer.FindAllStringSubmatch(header, -1) {
			s := strings.TrimSpace(m[1])
			lhead := strings.ToLower(strings.SplitN(s, "/", 2)[0])
			if commonServerBlacklist[lhead] {
				continue
			}
			if isUsefulFP(s) {
				servers[s] = true
			}
		}
		// 4) X-Powered-By
		for _, m := range reXPoweredBy.FindAllStringSubmatch(banner, -1) {
			s := strings.TrimSpace(m[1])
			if isUsefulFP(s) {
				banners[s] = true
			}
		}
	}

	return Fingerprints{
		BodyKeywords:  sortedKeys(bodyKW),
		TitleKeywords: sortedKeys(titleKW),
		ServerHeaders: sortedKeys(servers),
		BannerStrings: sortedKeys(banners),
	}
}

func isUsefulFP(s string) bool {
	t := strings.ToLower(strings.TrimSpace(s))
	if len(t) < 4 || len(t) > 80 {
		return false
	}
	if genericBlacklist[t] {
		return false
	}
	return reUsefulCheck.MatchString(s)
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
