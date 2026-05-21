package binaryedge

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/imroc/req/v3"
	"github.com/tidwall/gjson"
	"github.com/wgpsec/ENScan/pkg/models"
	"github.com/wgpsec/ENScan/pkg/source"
)

// BinaryEdge 实现 BinaryEdge 搜索引擎
type BinaryEdge struct {
	*source.BaseSource
	client *req.Client
}

// NewBinaryEdge 创建 BinaryEdge
func NewBinaryEdge() *BinaryEdge {
	b := &BinaryEdge{
		BaseSource: source.NewBaseSource("binaryedge"),
	}
	b.buildClient()
	return b
}

// Name 返回名称
func (b *BinaryEdge) Name() string {
	return b.BaseSource.Name()
}

// Accepts 接受的输入类型
func (b *BinaryEdge) Accepts() []string {
	return []string{"domain", "ip", "keyword"}
}

// NeedsKey 是否需要 API Key
func (b *BinaryEdge) NeedsKey() bool {
	return true
}

// SetKey 设置 API Key
func (b *BinaryEdge) SetKey(key string) {
	b.BaseSource.SetKey(key)
	b.buildClient()
}

// SetConfig 设置配置
func (b *BinaryEdge) SetConfig(cfg map[string]any) error {
	_ = b.BaseSource.SetConfig(cfg)
	b.buildClient()
	return nil
}

// buildClient 构建 HTTP 客户端
func (b *BinaryEdge) buildClient() {
	c := req.C()
	c.SetTimeout(30 * time.Second)
	c.SetUserAgent("Mozilla/5.0 (compatible; Ghost/1.0)")
	if b.BaseSource.Key() != "" {
		c.SetCommonHeader("X-Key", b.BaseSource.Key())
	}
	b.client = c
}

// Search 执行搜索
func (b *BinaryEdge) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	if b.client == nil {
		b.buildClient()
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

	u := fmt.Sprintf("https://api.binaryedge.io/v2/query/search?query=%s&page=1&size=%d",
		url.QueryEscape(query), cfg.MaxAssets)
	resp, err := b.client.R().SetContext(ctx).Get(u)
	if err != nil {
		return nil, fmt.Errorf("request binaryedge: %w", err)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("binaryedge api status %d", resp.StatusCode)
	}
	body := resp.String()
	if !gjson.Valid(body) {
		return nil, fmt.Errorf("invalid json")
	}
	data := gjson.Parse(body)
	var allAssets []*models.Asset
	for _, item := range data.Get("events").Array() {
		target := item.Get("target").String()
		ip := item.Get("target.ip").String()
		port := item.Get("target.port").Int()
		protocol := item.Get("target.protocol").String()
		title := item.Get("target.title").String()
		country := item.Get("target.location.country").String()
		city := item.Get("target.location.city").String()
		asset := models.NewAsset().
			WithTitle(fmt.Sprintf("[BinaryEdge] %s (%s)", target, title)).
			WithHost(target).
			WithIP(ip).
			WithPort(int(port)).
			WithProtocol(protocol).
			WithTitle(title).
			WithCountry(country).
			WithCity(city).
			WithSource(b.Name()).
			WithTags("binaryedge", "asset").
			WithRaw("protocol", protocol).
			WithRaw("title", title).
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
