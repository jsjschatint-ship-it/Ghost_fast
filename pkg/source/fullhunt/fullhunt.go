//go:build broken_recovery
// +build broken_recovery

package fullhunt

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/imroc/req/v3"
	"github.com/tidwall/gjson"
	"github.com/wgpsec/ENScan/pkg/models"
	"github.com/wgpsec/ENScan/pkg/source"
)

// FullHunt 实现 FullHunt 搜索引擎
type FullHunt struct {
	*source.BaseSource
	client *req.Client
}

// NewFullHunt 创建 FullHunt
func NewFullHunt() *FullHunt {
	f := &FullHunt{
		BaseSource: source.NewBaseSource("fullhunt"),
	}
	f.buildClient()
	return f
}

// Name 返回名称
func (f *FullHunt) Name() string {
	return f.BaseSource.Name()
}

// Accepts 接受的输入类型
func (f *FullHunt) Accepts() []string {
	return []string{"domain", "ip", "keyword"}
}

// NeedsKey 是否需要 API Key
func (f *FullHunt) NeedsKey() bool {
	return true
}

// SetKey 设置 API Key
func (f *FullHunt) SetKey(key string) {
	f.BaseSource.SetKey(key)
	f.buildClient()
}

// SetConfig 设置配置
func (f *FullHunt) SetConfig(cfg map[string]any) error {
	_ = f.BaseSource.SetConfig(cfg)
	f.buildClient()
	return nil
}

// buildClient 构建 HTTP 客户端
func (f *FullHunt) buildClient() {
	c := req.C()
	c.SetTimeout(30 * time.Second)
	c.SetUserAgent("Mozilla/5.0 (compatible; Ghost/1.0)")
	if f.BaseSource.Key() != "" {
		c.SetCommonHeader("X-API-KEY", f.BaseSource.Key())
	}
	f.client = c
}

// Search 执行搜索
func (f *FullHunt) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	if f.client == nil {
		f.buildClient()
	}
	cfg := &source.SearchConfig{
		MaxAssets: 100,
	}
	for _, opt := range opts {
		opt(cfg)
	}
	if f.BaseSource.Key() == "" {
		return nil, fmt.Errorf("fullhunt needs api key")
	}

	// FullHunt v1 端点（search 已下线）：
	//   IP:      GET /api/v1/host/{ip}
	//   Domain:  GET /api/v1/domain/{domain}/subdomains
	var u string
	if isIP(target) {
		u = fmt.Sprintf("https://fullhunt.io/api/v1/host/%s", url.PathEscape(target))
	} else {
		u = fmt.Sprintf("https://fullhunt.io/api/v1/domain/%s/subdomains", url.PathEscape(target))
	}
	resp, err := f.client.R().SetContext(ctx).Get(u)
	if err != nil {
		return nil, fmt.Errorf("request fullhunt: %w", err)
	}
	if resp.StatusCode == 404 {
		return nil, nil
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("fullhunt api status %d", resp.StatusCode)
	}
	body := resp.String()
	if !gjson.Valid(body) {
		return nil, fmt.Errorf("invalid json")
	}
	data := gjson.Parse(body)
	var allAssets []*models.Asset

	// 域名场景：hosts 是子域名字符串数组
	for _, item := range data.Get("hosts").Array() {
		host := item.String()
		if host == "" {
			continue
		}
		asset := models.NewAsset().
			WithTitle(fmt.Sprintf("[FullHunt] %s", host)).
			WithHost(host).
			WithDomain(target).
			WithSource(f.Name()).
			WithTags("fullhunt", "subdomain")
		allAssets = append(allAssets, asset)
	}
	// IP 场景：host 对象数组
	for _, item := range data.Get("data").Array() {
		host := item.Get("host").String()
		ip := item.Get("ip").String()
		port := item.Get("port").Int()
		title := item.Get("title").String()
		service := item.Get("service").String()
		country := item.Get("country").String()
		city := item.Get("city").String()
		asset := models.NewAsset().
			WithTitle(fmt.Sprintf("[FullHunt] %s:%d (%s)", ip, port, title)).
			WithHost(host).WithIP(ip).WithPort(int(port)).
			WithTitle(title).WithService(service).
			WithCountry(country).WithCity(city).
			WithSource(f.Name()).
			WithTags("fullhunt", "asset").
			WithRaw("port", strconv.Itoa(int(port))).
			WithRaw("service", service)
		allAssets = append(allAssets, asset)
	}
	if len(allAssets) > cfg.MaxAssets {
		allAssets = allAssets[:cfg.MaxAssets]
	}
	return allAssets, nil
}

// 辅助函数
func isIP(s string) bool {
	// 简化实现，实际可用 net.ParseIP
	return strings.Contains(s, ".")
}
