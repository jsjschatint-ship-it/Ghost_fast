package leakix

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/imroc/req/v3"
	"github.com/tidwall/gjson"
	"github.com/wgpsec/ENScan/pkg/models"
	"github.com/wgpsec/ENScan/pkg/source"
)

// LeakIX 实现 LeakIX 泄露情报
type LeakIX struct {
	*source.BaseSource
	client *req.Client
}

// NewLeakIX 创建 LeakIX
func NewLeakIX() *LeakIX {
	l := &LeakIX{
		BaseSource: source.NewBaseSource("leakix"),
	}
	l.buildClient()
	return l
}

// Name 返回名称
func (l *LeakIX) Name() string {
	return l.BaseSource.Name()
}

// Accepts 接受的输入类型
func (l *LeakIX) Accepts() []string {
	return []string{"domain", "email", "keyword"}
}

// NeedsKey 是否需要 API Key
func (l *LeakIX) NeedsKey() bool {
	return true
}

// SetKey 设置 API Key
func (l *LeakIX) SetKey(key string) {
	l.BaseSource.SetKey(key)
	l.buildClient()
}

// SetConfig 设置配置
func (l *LeakIX) SetConfig(cfg map[string]any) error {
	_ = l.BaseSource.SetConfig(cfg)
	l.buildClient()
	return nil
}

// buildClient 构建 HTTP 客户端
func (l *LeakIX) buildClient() {
	c := req.C()
	c.SetTimeout(30 * time.Second)
	c.SetUserAgent("Mozilla/5.0 (compatible; Ghost/1.0)")
	if l.BaseSource.Key() != "" {
		c.SetCommonHeader("Authorization", "Bearer "+l.BaseSource.Key())
	}
	l.client = c
}

// Search 执行搜索
func (l *LeakIX) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	if l.client == nil {
		l.buildClient()
	}
	cfg := &source.SearchConfig{
		MaxAssets: 50,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	// LeakIX 公开 API：host/{ip|domain} 返回 JSON
	// （api/v1/search 已下线）
	l.client.SetCommonHeader("Accept", "application/json")
	u := fmt.Sprintf("https://leakix.net/host/%s", url.PathEscape(target))
	resp, err := l.client.R().SetContext(ctx).Get(u)
	if err != nil {
		return nil, fmt.Errorf("request leakix: %w", err)
	}
	if resp.StatusCode == 404 {
		return nil, nil
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("leakix api status %d", resp.StatusCode)
	}
	body := resp.String()
	if !gjson.Valid(body) {
		return nil, fmt.Errorf("invalid json")
	}
	data := gjson.Parse(body)
	var allAssets []*models.Asset
	for _, item := range data.Get("Services").Array() {
		ip := item.Get("ip").String()
		port := item.Get("port").Int()
		software := item.Get("software.name").String()
		summary := item.Get("summary").String()
		asset := models.NewAsset().
			WithTitle(fmt.Sprintf("[LeakIX] %s:%d %s", ip, port, software)).
			WithIP(ip).WithHost(target).WithDomain(target).
			WithSource(l.Name()).
			WithTags("leakix", "service").
			WithRaw("port", fmt.Sprintf("%d", port)).
			WithRaw("software", software).
			WithRaw("summary", summary)
		allAssets = append(allAssets, asset)
	}
	for _, item := range data.Get("Leaks").Array() {
		event := item.Get("event_type").String()
		host := item.Get("host").String()
		summary := item.Get("summary").String()
		asset := models.NewAsset().
			WithTitle(fmt.Sprintf("[LeakIX/leak] %s on %s", event, host)).
			WithHost(host).WithDomain(target).
			WithSource(l.Name()).
			WithTags("leakix", "leak", "event:"+event, "high-value").
			WithRaw("event_type", event).
			WithRaw("summary", summary)
		allAssets = append(allAssets, asset)
	}
	if len(allAssets) > cfg.MaxAssets {
		allAssets = allAssets[:cfg.MaxAssets]
	}
	return allAssets, nil
}
