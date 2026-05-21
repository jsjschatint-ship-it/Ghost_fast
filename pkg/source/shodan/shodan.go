package shodan

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

// Shodan 实现 Shodan 互联网资产查
type Shodan struct {
	*source.BaseSource
	client *req.Client
}

// NewShodan 创建 Shodan
func NewShodan() *Shodan {
	s := &Shodan{
		BaseSource: source.NewBaseSource("shodan"),
	}
	s.buildClient()
	return s
}

// Name 返回名称
func (s *Shodan) Name() string {
	return s.BaseSource.Name()
}

// Accepts 接受的输入类型
func (s *Shodan) Accepts() []string {
	return []string{"ip", "domain", "keyword"}
}

// NeedsKey 是否需要 API Key
func (s *Shodan) NeedsKey() bool {
	return true
}

// SetKey 设置 API Key
func (s *Shodan) SetKey(key string) {
	s.BaseSource.SetKey(key)
	s.buildClient()
}

// SetConfig 设置配置
func (s *Shodan) SetConfig(cfg map[string]any) error {
	_ = s.BaseSource.SetConfig(cfg)
	s.buildClient()
	return nil
}

// buildClient 构建 HTTP 客户端
func (s *Shodan) buildClient() {
	c := req.C()
	c.SetTimeout(30 * time.Second)
	c.SetUserAgent("Mozilla/5.0 (compatible; Ghost/1.0)")
	if s.BaseSource.Key() != "" {
		c.SetCommonHeader("Authorization", "Bearer "+s.BaseSource.Key())
	}
	s.client = c
}

// Search 执行搜索
func (s *Shodan) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	if s.client == nil {
		s.buildClient()
	}
	cfg := &source.SearchConfig{
		MaxAssets: 100,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	// 构造查询语句
	var query string
	if isIP(target) {
		query = fmt.Sprintf("ip:%s", target)
	} else {
		query = fmt.Sprintf("hostname:%s", target)
	}

	u := fmt.Sprintf("https://api.shodan.io/shodan/host/search?key=%s&query=%s&limit=%d",
		s.BaseSource.Key(), url.QueryEscape(query), cfg.MaxAssets)
	resp, err := s.client.R().SetContext(ctx).Get(u)
	if err != nil {
		return nil, fmt.Errorf("request shodan: %w", err)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("shodan api status %d", resp.StatusCode)
	}
	body := resp.String()
	if !gjson.Valid(body) {
		return nil, fmt.Errorf("invalid json")
	}
	data := gjson.Parse(body)
	var allAssets []*models.Asset
	for _, item := range data.Get("matches").Array() {
		ip := item.Get("ip_str").String()
		port := item.Get("port").Int()
		hostnames := item.Get("hostnames").Array()
		var hostname string
		if len(hostnames) > 0 {
			hostname = hostnames[0].String()
		}
		title := item.Get("title").String()
		product := item.Get("product").String()
		os := item.Get("os").String()
		country := item.Get("location.country_name").String()
		city := item.Get("location.city").String()
		org := item.Get("org").String()
		asset := models.NewAsset().
			WithTitle(fmt.Sprintf("[Shodan] %s:%d (%s)", ip, port, title)).
			WithHost(hostname).
			WithIP(ip).
			WithPort(int(port)).
			WithTitle(title).
			WithProduct(product).
			WithOS(os).
			WithCountry(country).
			WithCity(city).
			WithOrg(org).
			WithSource(s.Name()).
			WithTags("shodan", "asset").
			WithRaw("port", strconv.Itoa(int(port))).
			WithRaw("title", title).
			WithRaw("product", product).
			WithRaw("os", os).
			WithRaw("country", country).
			WithRaw("city", city).
			WithRaw("org", org)
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
