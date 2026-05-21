//go:build broken_recovery
// +build broken_recovery

package bgpview

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/imroc/req/v3"
	"github.com/tidwall/gjson"
	"github.com/wgpsec/ENScan/pkg/models"
	"github.com/wgpsec/ENScan/pkg/source"
)

// BGPView 实现 BGPView 查询
type BGPView struct {
	*source.BaseSource
	client *req.Client
}

// NewBGPView 创建 BGPView
func NewBGPView() *BGPView {
	s := &BGPView{
		BaseSource: source.NewBaseSource("bgpview"),
	}
	s.buildClient()
	return s
}

// Name 返回名称
func (s *BGPView) Name() string {
	return s.BaseSource.Name()
}

// Accepts 接受的输入类型
func (s *BGPView) Accepts() []string {
	return []string{"ip", "asn", "domain"}
}

// NeedsKey 是否需要 API Key
func (s *BGPView) NeedsKey() bool {
	return false
}

// SetConfig 设置配置
func (s *BGPView) SetConfig(cfg map[string]any) error {
	_ = s.BaseSource.SetConfig(cfg)
	s.buildClient()
	return nil
}

// buildClient 构建 HTTP 客户端
func (s *BGPView) buildClient() {
	c := req.C()
	c.SetTimeout(30 * time.Second)
	c.SetUserAgent("Mozilla/5.0 (compatible; Ghost/1.0)")
	s.client = c
}

// Search 执行搜索
func (s *BGPView) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	cfg := &source.SearchConfig{
		MaxAssets: 50,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	var allAssets []*models.Asset
	// IP 查询
	if isIP(target) {
		if assets, err := s.queryIP(ctx, target); err == nil {
			allAssets = append(allAssets, assets...)
		}
	}
	// ASN 查询
	if asn := extractASN(target); asn != "" {
		if assets, err := s.queryASN(ctx, asn); err == nil {
			allAssets = append(allAssets, assets...)
		}
	}
	// 域名解析到 IP 再查
	if isDomain(target) {
		// BGPView 域名查询：通过 IP 接口（接受 hostname，会自动解析）
		if assets, err := s.queryIP(ctx, target); err == nil {
			allAssets = append(allAssets, assets...)
		}
	}

	if len(allAssets) > cfg.MaxAssets {
		allAssets = allAssets[:cfg.MaxAssets]
	}
	return allAssets, nil
}

// queryIP 查询 IP
func (s *BGPView) queryIP(ctx context.Context, ip string) ([]*models.Asset, error) {
	u := fmt.Sprintf("https://bgpview.io/ip/%s", ip)
	resp, err := s.client.R().SetContext(ctx).Get(u)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("bgpview ip status %d", resp.StatusCode)
	}
	body := resp.String()
	if !gjson.Valid(body) {
		return nil, fmt.Errorf("invalid json")
	}
	data := gjson.Parse(body)
	var assets []*models.Asset
	// 解析 ASN
	for _, item := range data.Get("data.asns").Array() {
		asn := item.Get("asn").String()
		org := item.Get("name").String()
		country := item.Get("country_code").String()
		asset := models.NewAsset().
			WithTitle(fmt.Sprintf("[BGPView] %s (%s)", asn, org)).
			WithIP(ip).
			WithASN(asn).
			WithOrg(org).
			WithCountry(country).
			WithSource(s.Name()).
			WithTags("bgp", "asn").
			WithRaw("rir", item.Get("rir").String()).
			WithRaw("allocated", item.Get("allocated").String())
		assets = append(assets, asset)
	}
	// 解析前缀
	for _, item := range data.Get("data.prefixes").Array() {
		prefix := item.Get("prefix").String()
		rir := item.Get("rir").String()
		asset := models.NewAsset().
			WithTitle(fmt.Sprintf("[BGPView] %s (%s)", prefix, rir)).
			WithIP(ip).
			WithSource(s.Name()).
			WithTags("bgp", "prefix").
			WithRaw("prefix", prefix).
			WithRaw("rir", rir)
		assets = append(assets, asset)
	}
	return assets, nil
}

// queryASN 查询 ASN
func (s *BGPView) queryASN(ctx context.Context, asn string) ([]*models.Asset, error) {
	u := fmt.Sprintf("https://bgpview.io/asn/%s", asn)
	resp, err := s.client.R().SetContext(ctx).Get(u)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("bgpview asn status %d", resp.StatusCode)
	}
	body := resp.String()
	if !gjson.Valid(body) {
		return nil, fmt.Errorf("invalid json")
	}
	data := gjson.Parse(body)
	var assets []*models.Asset
	// 基本信息
	name := data.Get("data.name").String()
	country := data.Get("data.country_code").String()
	asset := models.NewAsset().
		WithTitle(fmt.Sprintf("[BGPView] %s (%s)", asn, name)).
		WithASN(asn).
		WithOrg(name).
		WithCountry(country).
		WithSource(s.Name()).
		WithTags("bgp", "asn").
		WithRaw("rir", data.Get("data.rir").String()).
		WithRaw("allocated", data.Get("data.allocated").String())
	assets = append(assets, asset)
	// 前缀
	for _, item := range data.Get("data.prefixes.ipv4").Array() {
		prefix := item.Get("prefix").String()
		asset := models.NewAsset().
			WithTitle(fmt.Sprintf("[BGPView] %s (%s)", prefix, asn)).
			WithASN(asn).
			WithSource(s.Name()).
			WithTags("bgp", "prefix").
			WithRaw("prefix", prefix).
			WithRaw("asn", asn)
		assets = append(assets, asset)
	}
	return assets, nil
}

// 辅助函数
func isIP(s string) bool {
	// 简化实现，实际可用 net.ParseIP
	return strings.Contains(s, ".")
}

func isDomain(s string) bool {
	return !isIP(s) && !strings.Contains(s, "AS")
}

func extractASN(s string) string {
	if strings.HasPrefix(strings.ToUpper(s), "AS") {
		return strings.ToUpper(s)
	}
	return ""
}
