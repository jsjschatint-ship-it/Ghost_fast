// Package pivots 供应链横向枢纽（基于 FOFA 的 4 大反查）。
//
// 给一个目标域名 → 自动提取 ICP/cert_org/icon_hash/tracker → 在 FOFA 反查
// 出"同主体的兄弟资产"，全部打 supply-* 标签。
package pivots

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

// 字段集合
const (
	fpFields       = "host,link,domain,ip,port,icp,cert,icon_hash,banner"
	fpFieldsNoIcon = "host,link,domain,ip,port,icp,cert,banner"
	bodyFields     = "host,body"
)

// Pivot 类型 → FOFA 反查字段
var PivotToField = map[string]string{
	"icp":       "icp",
	"cert_org":  "cert",
	"icon_hash": "icon_hash",
	"tracker":   "body",
}

var (
	reTracker      = regexp.MustCompile(`\b(UA-\d{4,}-\d{1,3}|G-[A-Z0-9]{8,12}|GTM-[A-Z0-9]{6,8})\b`)
	reBaidu        = regexp.MustCompile(`hm\.baidu\.com/hm\.js\?([a-f0-9]{20,})`)
	reCNZZ         = regexp.MustCompile(`s\d+\.cnzz\.com/[^"']+\?(?:id=)?(\d+)`)
	reCertOLDAP    = regexp.MustCompile(`(?i)O=([^,/\n\r]+)`)
	reCertOMulti   = regexp.MustCompile(`(?im)^\s*Organization:\s*([^\n\r]+)`)
	reCertSubject  = regexp.MustCompile(`(?i)Subject:\s*\n((?:\s+[^\n]+\n?)+)`)
	genericCertOrg = map[string]bool{
		"digicert inc": true, "let's encrypt": true, "globalsign nv-sa": true,
		"godaddy.com, inc.": true, "sectigo limited": true, "amazon": true,
		"google trust services": true, "cloudflare, inc.": true, "zerossl": true,
		"tencent technologies (shenzhen) company limited": true,
		"tencent cloud computing (beijing) co.":           true,
		"alibaba (china) technology co., ltd.":            true,
	}
)

// Fingerprints 提取的指纹集合
type Fingerprints struct {
	ICP      []string `json:"icp"`
	CertOrg  []string `json:"cert_org"`
	IconHash []string `json:"icon_hash"`
	Tracker  []string `json:"tracker"`
}

// Pivots 数据源
type Pivots struct {
	*source.BaseSource
	fofa *fofahelper.Client
}

// New 创建
func New() *Pivots {
	return &Pivots{
		BaseSource: source.NewBaseSource("supply_pivots"),
		fofa:       fofahelper.New(""),
	}
}

// Accepts 接受的输入类型
func (p *Pivots) Accepts() []string { return []string{"domain"} }

// NeedsKey 是否需要 API Key
func (p *Pivots) NeedsKey() bool { return true }

// SetConfig 设置配置（fofa_key/fofa_email/proxy/timeout）
func (p *Pivots) SetConfig(cfg map[string]any) error {
	_ = p.BaseSource.SetConfig(cfg)
	if v, ok := cfg["fofa_key"].(string); ok && v != "" {
		p.fofa.Key = v
	} else if v, ok := cfg["key"].(string); ok && v != "" {
		p.fofa.Key = v
	}
	if v, ok := cfg["fofa_email"].(string); ok {
		p.fofa.Email = v
	}
	if v, ok := cfg["proxy"].(string); ok && v != "" {
		p.fofa.Proxy = v
	}
	if v, ok := cfg["timeout"].(int); ok && v > 0 {
		p.fofa.Timeout = time.Duration(v) * time.Second
	}
	return nil
}

// SetKey 透传 FOFA key
func (p *Pivots) SetKey(k string) {
	p.BaseSource.SetKey(k)
	p.fofa.Key = k
}

// Search 执行搜索
func (p *Pivots) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	cfg := &source.SearchConfig{MaxAssets: 1000}
	for _, opt := range opts {
		opt(cfg)
	}
	domain := strings.TrimSpace(target)
	if domain == "" {
		return nil, nil
	}
	if p.fofa.Key == "" {
		return nil, fmt.Errorf("supply_pivots needs fofa_key")
	}

	fps := p.ExtractFingerprints(ctx, domain, 50)
	maxPer := cfg.MaxAssets
	if maxPer <= 0 {
		maxPer = 1000
	}
	var all []*models.Asset
	for pivotType, field := range PivotToField {
		var values []string
		switch pivotType {
		case "icp":
			values = fps.ICP
		case "cert_org":
			values = fps.CertOrg
		case "icon_hash":
			values = fps.IconHash
		case "tracker":
			values = fps.Tracker
		}
		for _, v := range values {
			rs, err := p.fofa.SearchPaginated(ctx, fmt.Sprintf(`%s="%s"`, field, v), "host,link,domain,ip,port,title", maxPer)
			if err != nil {
				continue
			}
			tag := "supply-" + pivotType
			for _, r := range rs {
				host, ip, port, title, dom, urlStr := fofahelper.RowToAssetFields(r)
				a := models.NewAsset().
					WithHost(host).WithIP(ip).WithPort(port).
					WithTitle(title).WithDomain(dom).WithURL(urlStr).
					WithSource("fofa-supply").WithTags(tag)
				a.Normalize()
				all = append(all, a)
			}
		}
	}
	return all, nil
}

// ExtractFingerprints 通过 FOFA 拉样本资产，提取可反查指纹
func (p *Pivots) ExtractFingerprints(ctx context.Context, domain string, sample int) Fingerprints {
	icp := map[string]bool{}
	certOrg := map[string]bool{}
	iconHash := map[string]bool{}
	tracker := map[string]bool{}

	queries := []string{
		fmt.Sprintf(`host="%s"`, domain),
		fmt.Sprintf(`host="www.%s"`, domain),
		fmt.Sprintf(`domain="%s"`, domain),
	}
	var rows []fofahelper.Row
	for _, q := range queries {
		r, err := p.fofa.Search(ctx, q, fpFields, sample)
		if err != nil {
			r, _ = p.fofa.Search(ctx, q, fpFieldsNoIcon, sample)
		}
		rows = append(rows, r...)
		for _, x := range r {
			if x["icp"] != "" {
				goto done
			}
		}
	}
done:
	for _, r := range rows {
		if v := strings.TrimSpace(r["icp"]); v != "" {
			icp[v] = true
		}
		cert := r["cert"]
		if cert != "" {
			subBlock := ""
			if m := reCertSubject.FindStringSubmatch(cert); len(m) > 1 {
				subBlock = m[1]
			}
			for _, m := range reCertOMulti.FindAllStringSubmatch(subBlock, -1) {
				org := strings.Trim(strings.Trim(strings.TrimSpace(m[1]), "\""), "'")
				if org != "" && !genericCertOrg[strings.ToLower(org)] {
					certOrg[org] = true
				}
			}
			for _, m := range reCertOLDAP.FindAllStringSubmatch(cert, -1) {
				org := strings.Trim(strings.Trim(strings.TrimSpace(m[1]), "\""), "'")
				if org != "" && !genericCertOrg[strings.ToLower(org)] {
					certOrg[org] = true
				}
			}
		}
		if h := r["icon_hash"]; h != "" && h != "0" && h != "None" {
			iconHash[h] = true
		}
		if banner := r["banner"]; banner != "" {
			for _, m := range reTracker.FindAllStringSubmatch(banner, -1) {
				tracker[m[1]] = true
			}
		}
	}

	// body 单独拉抓 tracker
	bodyRows, _ := p.fofa.Search(ctx, fmt.Sprintf(`host="%s" || host="www.%s"`, domain, domain), bodyFields, 2)
	for _, r := range bodyRows {
		body := r["body"]
		for _, m := range reTracker.FindAllStringSubmatch(body, -1) {
			tracker[m[1]] = true
		}
		for _, m := range reBaidu.FindAllStringSubmatch(body, -1) {
			tracker["hm.js?"+m[1]] = true
		}
		for _, m := range reCNZZ.FindAllStringSubmatch(body, -1) {
			tracker["cnzz-"+m[1]] = true
		}
	}

	return Fingerprints{
		ICP:      sortedKeys(icp),
		CertOrg:  sortedKeys(certOrg),
		IconHash: sortedKeys(iconHash),
		Tracker:  sortedKeys(tracker),
	}
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
