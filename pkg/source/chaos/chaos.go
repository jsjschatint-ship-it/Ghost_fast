//go:build broken_recovery
// +build broken_recovery

package chaos

import (
	"context"
	"fmt"
	"time"

	"github.com/imroc/req/v3"
	"github.com/tidwall/gjson"
	"github.com/wgpsec/ENScan/pkg/models"
	"github.com/wgpsec/ENScan/pkg/source"
)

// Chaos 实现 Chaos 客户
type Chaos struct {
	*source.BaseSource
	client *req.Client
}

// NewChaos 创建 Chaos
func NewChaos() *Chaos {
	c := &Chaos{
		BaseSource: source.NewBaseSource("chaos"),
	}
	c.buildClient()
	return c
}

// Name 返回名称
func (c *Chaos) Name() string {
	return c.BaseSource.Name()
}

// Accepts 接受的输入类型
func (c *Chaos) Accepts() []string {
	return []string{"domain"}
}

// NeedsKey 是否需要 API Key
func (c *Chaos) NeedsKey() bool {
	return true
}

// SetKey 设置 API Key
func (c *Chaos) SetKey(key string) {
	c.BaseSource.SetKey(key)
	c.buildClient()
}

// SetConfig 设置配置
func (c *Chaos) SetConfig(cfg map[string]any) error {
	_ = c.BaseSource.SetConfig(cfg)
	c.buildClient()
	return nil
}

// buildClient 构建 HTTP 客户端
func (c *Chaos) buildClient() {
	client := req.C()
	client.SetTimeout(30 * time.Second)
	client.SetUserAgent("Mozilla/5.0 (compatible; Ghost/1.0)")
	if c.BaseSource.Key() != "" {
		client.SetCommonHeader("Authorization", "Bearer "+c.BaseSource.Key())
	}
	c.client = client
}

// Search 执行搜索
func (c *Chaos) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	if c.client == nil {
		c.buildClient()
	}
	cfg := &source.SearchConfig{
		MaxAssets: 200,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	// Chaos 子域名枚
	u := fmt.Sprintf("https://dns.projectdiscovery.io/dns/%s/subdomains", target)
	resp, err := c.client.R().SetContext(ctx).Get(u)
	if err != nil {
		return nil, fmt.Errorf("request chaos: %w", err)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("chaos api status %d", resp.StatusCode)
	}
	body := resp.String()
	if !gjson.Valid(body) {
		return nil, fmt.Errorf("invalid json")
	}
	data := gjson.Parse(body)
	var allAssets []*models.Asset
	for _, item := range data.Get("subdomains").Array() {
		label := item.String()
		if label == "" {
			continue
		}
		// Chaos 返回相对标签（"www" 而非 "www.example.com"）
		fqdn := label + "." + target
		asset := models.NewAsset().
			WithTitle(fmt.Sprintf("[Chaos] %s", fqdn)).
			WithHost(fqdn).
			WithDomain(target).
			WithSource(c.Name()).
			WithTags("chaos", "subdomain").
			WithRaw("subdomain", fqdn)
		allAssets = append(allAssets, asset)
	}
	if len(allAssets) > cfg.MaxAssets {
		allAssets = allAssets[:cfg.MaxAssets]
	}
	return allAssets, nil
}
