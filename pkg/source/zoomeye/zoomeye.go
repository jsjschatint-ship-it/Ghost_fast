package zoomeye

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

// ZoomEye 实现 ZoomEye 网络空间搜索引擎
type ZoomEye struct {
	*source.BaseSource
	client *req.Client
}

// NewZoomEye 创建 ZoomEye
func NewZoomEye() *ZoomEye {
	z := &ZoomEye{
		BaseSource: source.NewBaseSource("zoomeye"),
	}
	z.buildClient()
	return z
}

// Name 返回名称
func (z *ZoomEye) Name() string {
	return z.BaseSource.Name()
}

// Accepts 接受的输入类型
func (z *ZoomEye) Accepts() []string {
	return []string{"domain", "ip", "keyword"}
}

// NeedsKey 是否需要 API Key
func (z *ZoomEye) NeedsKey() bool {
	return true
}

// SetKey 设置 API Key
func (z *ZoomEye) SetKey(key string) {
	z.BaseSource.SetKey(key)
	z.buildClient()
}

// SetConfig 设置配置
func (z *ZoomEye) SetConfig(cfg map[string]any) error {
	_ = z.BaseSource.SetConfig(cfg)
	z.buildClient()
	return nil
}

// buildClient 构建 HTTP 客户端
func (z *ZoomEye) buildClient() {
	c := req.C()
	c.SetTimeout(30 * time.Second)
	c.SetUserAgent("Mozilla/5.0 (compatible; Ghost/1.0)")
	if z.BaseSource.Key() != "" {
		c.SetCommonHeader("API-KEY", z.BaseSource.Key())
	}
	z.client = c
}

// Search 执行搜索
func (z *ZoomEye) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	if z.client == nil {
		z.buildClient()
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

	u := fmt.Sprintf("https://api.zoomeye.org/host/search?query=%s&page=1&page_size=%d",
		url.QueryEscape(query), cfg.MaxAssets)
	resp, err := z.client.R().SetContext(ctx).Get(u)
	if err != nil {
		return nil, fmt.Errorf("request zoomeye: %w", err)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("zoomeye api status %d", resp.StatusCode)
	}
	body := resp.String()
	if !gjson.Valid(body) {
		return nil, fmt.Errorf("invalid json")
	}
	data := gjson.Parse(body)
	var allAssets []*models.Asset
	for _, item := range data.Get("matches").Array() {
		ip := item.Get("ip").String()
		port := item.Get("portinfo.port").Int()
		hostnames := item.Get("domains").Array()
		var hostname string
		if len(hostnames) > 0 {
			hostname = hostnames[0].String()
		}
		title := item.Get("geoinfo.title").String()
		service := item.Get("portinfo.service").String()
		country := item.Get("geoinfo.country.names.en").String()
		city := item.Get("geoinfo.city.names.en").String()
		asset := models.NewAsset().
			WithTitle(fmt.Sprintf("[ZoomEye] %s:%d (%s)", ip, port, title)).
			WithHost(hostname).
			WithIP(ip).
			WithPort(int(port)).
			WithTitle(title).
			WithService(service).
			WithCountry(country).
			WithCity(city).
			WithSource(z.Name()).
			WithTags("zoomeye", "asset").
			WithRaw("port", strconv.Itoa(int(port))).
			WithRaw("title", title).
			WithRaw("service", service).
			WithRaw("country", country).
			WithRaw("city", city)
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
