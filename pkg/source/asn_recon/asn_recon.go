//go:build broken_recovery
// +build broken_recovery

package asn_recon

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/imroc/req/v3"
	"github.com/tidwall/gjson"
	"github.com/wgpsec/ENScan/pkg/models"
	"github.com/wgpsec/ENScan/pkg/runner"
	"github.com/wgpsec/ENScan/pkg/source"
)

// ASNRecon 实现 ASN 网段扫探（双模式编排器）
type ASNRecon struct {
	*source.BaseSource
	client *req.Client
}

// NewASNRecon 创建 ASNRecon
func NewASNRecon() *ASNRecon {
	s := &ASNRecon{
		BaseSource: source.NewBaseSource("asn_recon"),
	}
	s.buildClient()
	return s
}

// Name 返回名称
func (s *ASNRecon) Name() string {
	return s.BaseSource.Name()
}

// Accepts 接受的输入类型
func (s *ASNRecon) Accepts() []string {
	return []string{"domain", "company", "ip", "asn"}
}

// NeedsKey 是否需要 API Key
func (s *ASNRecon) NeedsKey() bool {
	return false
}

// SetConfig 设置配置
func (s *ASNRecon) SetConfig(cfg map[string]any) error {
	_ = s.BaseSource.SetConfig(cfg)
	s.buildClient()
	return nil
}

// buildClient 构建 HTTP 客户端
func (s *ASNRecon) buildClient() {
	c := req.C()
	c.SetTimeout(30 * time.Second)
	c.SetUserAgent("Mozilla/5.0 (compatible; Ghost/1.0)")
	s.client = c
}

// Search 执行搜索
func (s *ASNRecon) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	cfg := &source.SearchConfig{
		MaxAssets: 200,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	// 1) target -> ASN
	asn, err := s.resolveASN(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("resolve ASN: %w", err)
	}

	// 2) ASN -> CIDR 列表
	cidrs, err := s.fetchCIDRs(ctx, asn)
	if err != nil {
		return nil, fmt.Errorf("fetch CIDRs: %w", err)
	}
	if len(cidrs) == 0 {
		return nil, fmt.Errorf("no CIDRs for ASN %s", asn)
	}

	// 3) CIDR × {80,443} 存活 IP
	var allAssets []*models.Asset
	var mu sync.Mutex
	var wg sync.WaitGroup

	// 并发扫描每个 CIDR
	for _, cidr := range cidrs {
		wg.Add(1)
		go func(c string) {
			defer wg.Done()
			assets, err := s.scanCIDR(ctx, c, cfg)
			if err != nil {
				return
			}
			mu.Lock()
			allAssets = append(allAssets, assets...)
			mu.Unlock()
		}(cidr)
	}
	wg.Wait()

	if len(allAssets) > cfg.MaxAssets {
		allAssets = allAssets[:cfg.MaxAssets]
	}
	return allAssets, nil
}

// resolveASN 解析目标到 ASN
func (s *ASNRecon) resolveASN(ctx context.Context, target string) (string, error) {
	// 1) 检查是否已经是 ASN（ASxxxx 或纯数字）
	if asn := s.extractASN(target); asn != "" {
		return asn, nil
	}

	// 2) 域名/IP -> ASN（BGPView API）
	// 先尝试域名
	if isDomain(target) {
		return s.queryASNByDomain(ctx, target)
	}
	// 再尝试 IP
	if isIP(target) {
		return s.queryASNByIP(ctx, target)
	}

	// 3) 公司名称 -> ASN（BGPView Search）
	return s.queryASNByCompany(ctx, target)
}

// extractASN 从字符串提取 ASN
func (s *ASNRecon) extractASN(input string) string {
	re := regexp.MustCompile(`(?i)AS(\d+)`)
	m := re.FindStringSubmatch(input)
	if len(m) > 1 {
		return "AS" + m[1]
	}
	// 纯数字
	reNum := regexp.MustCompile(`^\d+$`)
	if reNum.MatchString(input) {
		return "AS" + input
	}
	return ""
}

// queryASNByDomain 通过域名查 ASN（BGPView Search）
func (s *ASNRecon) queryASNByDomain(ctx context.Context, domain string) (string, error) {
	u := fmt.Sprintf("https://bgpview.io/search?searchTerm=%s", domain)
	resp, err := s.client.R().SetContext(ctx).Get(u)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("bgpview search status %d", resp.StatusCode)
	}
	body := resp.String()
	if !gjson.Valid(body) {
		return "", fmt.Errorf("invalid json")
	}
	data := gjson.Parse(body)
	asn := data.Get("data.asns.0.asn").String()
	if asn == "" {
		return "", fmt.Errorf("no ASN found for domain %s", domain)
	}
	return asn, nil
}

// queryASNByIP 通过 IP 查 ASN（BGPView IP API）
func (s *ASNRecon) queryASNByIP(ctx context.Context, ip string) (string, error) {
	u := fmt.Sprintf("https://bgpview.io/ip/%s", ip)
	resp, err := s.client.R().SetContext(ctx).Get(u)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("bgpview ip status %d", resp.StatusCode)
	}
	body := resp.String()
	if !gjson.Valid(body) {
		return "", fmt.Errorf("invalid json")
	}
	data := gjson.Parse(body)
	asn := data.Get("data.asns.0.asn").String()
	if asn == "" {
		return "", fmt.Errorf("no ASN found for IP %s", ip)
	}
	return asn, nil
}

// queryASNByCompany 通过公司名称查 ASN（BGPView Search）
func (s *ASNRecon) queryASNByCompany(ctx context.Context, company string) (string, error) {
	u := fmt.Sprintf("https://bgpview.io/search?searchTerm=%s", company)
	resp, err := s.client.R().SetContext(ctx).Get(u)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("bgpview search status %d", resp.StatusCode)
	}
	body := resp.String()
	if !gjson.Valid(body) {
		return "", fmt.Errorf("invalid json")
	}
	data := gjson.Parse(body)
	asn := data.Get("data.asns.0.asn").String()
	if asn == "" {
		return "", fmt.Errorf("no ASN found for company %s", company)
	}
	return asn, nil
}

// fetchCIDRs 获取 ASN 的 CIDR 列表
func (s *ASNRecon) fetchCIDRs(ctx context.Context, asn string) ([]string, error) {
	u := fmt.Sprintf("https://bgpview.io/asn/%s/prefixes", asn)
	resp, err := s.client.R().SetContext(ctx).Get(u)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("bgpview prefixes status %d", resp.StatusCode)
	}
	body := resp.String()
	if !gjson.Valid(body) {
		return nil, fmt.Errorf("invalid json")
	}
	data := gjson.Parse(body)
	var cidrs []string
	for _, item := range data.Get("data.ipv4_prefixes").Array() {
		prefix := item.Get("prefix").String()
		if prefix != "" {
			cidrs = append(cidrs, prefix)
		}
	}
	return cidrs, nil
}

// scanCIDR 扫描 CIDR（passive + active）
func (s *ASNRecon) scanCIDR(ctx context.Context, cidr string, cfg *source.SearchConfig) ([]*models.Asset, error) {
	var assets []*models.Asset

	// Passive: 查 FOFA/Shodan/Quake/ZoomEye/Censys（这里仅示例 FOFA）
	passiveAssets, err := s.scanPassive(ctx, cidr)
	if err == nil {
		assets = append(assets, passiveAssets...)
	}

	// Active: 本地 naabu + httpx（可选，需要二进制在 PATH）
	// 从配置读取是否启用 active 模式
	if enableActive, ok := cfg.Extra["enable_active"].(bool); ok && enableActive {
		proxy := ""
		if p, ok := cfg.Extra["proxy"].(string); ok {
			proxy = p
		}
		ports := []int{80, 443}
		if pts, ok := cfg.Extra["active_ports"].([]int); ok {
			ports = pts
		}
		scanner := runner.NewActiveScanner(proxy, ports)
		activeAssets, err := scanner.ScanCIDR(ctx, cidr)
		if err == nil {
			assets = append(assets, activeAssets...)
		}
	}

	return assets, nil
}

// scanPassive 被动模式：查 FOFA 等已有索引
func (s *ASNRecon) scanPassive(ctx context.Context, cidr string) ([]*models.Asset, error) {
	// FOFA query: cidr=1.2.3.0/24
	query := fmt.Sprintf("cidr=%s", cidr)
	u := fmt.Sprintf("https://fofa.info/api/v1/search/all")
	q := fmt.Sprintf("qbase64=%s", base64.StdEncoding.EncodeToString([]byte(query)))
	fullURL := u + "?" + q

	resp, err := s.client.R().SetContext(ctx).Get(fullURL)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("fofa api status %d", resp.StatusCode)
	}
	body := resp.String()
	if !gjson.Valid(body) {
		return nil, fmt.Errorf("invalid json")
	}
	data := gjson.Parse(body)
	var assets []*models.Asset
	for _, item := range data.Get("results").Array() {
		host := item.Get("host").String()
		ip := item.Get("ip").String()
		port := item.Get("port").Int()
		title := item.Get("title").String()
		asset := models.NewAsset().
			WithTitle(fmt.Sprintf("[ASN] %s:%d (%s)", ip, port, title)).
			WithHost(host).
			WithIP(ip).
			WithSource(s.Name()).
			WithTags("asn", "passive", "fofa").
			WithRaw("cidr", cidr).
			WithRaw("port", strconv.Itoa(int(port))).
			WithRaw("title", title)
		assets = append(assets, asset)
	}
	return assets, nil
}

// 辅助函数
func isDomain(s string) bool {
	return !isIP(s) && !strings.Contains(s, "AS")
}

func isIP(s string) bool {
	return net.ParseIP(s) != nil
}
