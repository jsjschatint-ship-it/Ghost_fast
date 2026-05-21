//go:build broken_recovery
// +build broken_recovery

package intelx

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

const (
	defaultIntelXURL = "https://2.intelx.io"
	defaultSize      = 100
)

// IntelX 实现 IntelX 情报平台
type IntelX struct {
	*source.BaseSource
	client  *req.Client
	baseURL string
}

// NewIntelX 创建 IntelX
func NewIntelX() *IntelX {
	i := &IntelX{
		BaseSource: source.NewBaseSource("intelx"),
		baseURL:    defaultIntelXURL,
	}
	i.buildClient()
	return i
}

// Name 返回名称
func (i *IntelX) Name() string {
	return i.BaseSource.Name()
}

// Accepts 接受的输入类型
func (i *IntelX) Accepts() []string {
	return []string{"domain", "email", "ip", "keyword"}
}

// NeedsKey 是否需要 API Key
func (i *IntelX) NeedsKey() bool {
	return true
}

// SetKey 设置 API Key
func (i *IntelX) SetKey(key string) {
	i.BaseSource.SetKey(key)
	i.buildClient()
}

// SetConfig 设置配置
func (i *IntelX) SetConfig(cfg map[string]any) error {
	_ = i.BaseSource.SetConfig(cfg)
	i.buildClient()
	return nil
}

// buildClient 构建 HTTP 客户端
func (i *IntelX) buildClient() {
	c := req.C()
	c.SetTimeout(30 * time.Second)
	c.SetUserAgent("Mozilla/5.0 (compatible; Ghost/1.0)")
	if i.BaseSource.Key() != "" {
		c.SetCommonHeader("x-key", i.BaseSource.Key())
	}
	i.client = c
}

// Search 执行搜索
func (i *IntelX) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	if i.client == nil {
		i.buildClient()
	}
	cfg := &source.SearchConfig{
		MaxAssets: 100,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	// IntelX 无需单独 init，直接 POST /intelligent/search（凭 x-key 认证）
	// 构造搜索请求
	searchReq := map[string]any{
		"term":       target,
		"maxresults": cfg.MaxAssets,
		"media":      0,
		"target":     5, // 5=domains, emails, etc.
	}
	u := i.baseURL + "/intelligent/search"
	resp, err := i.client.R().
		SetContext(ctx).
		SetHeader("Content-Type", "application/json").
		SetBodyJsonMarshal(searchReq).
		Post(u)
	if err != nil {
		return nil, fmt.Errorf("search request: %w", err)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("intelx search status %d", resp.StatusCode)
	}
	body := resp.String()
	if !gjson.Valid(body) {
		return nil, fmt.Errorf("invalid json")
	}
	data := gjson.Parse(body)
	id := data.Get("id").String()
	if id == "" {
		return nil, fmt.Errorf("no search id")
	}

	// 轮询结果
	var allAssets []*models.Asset
	for start := time.Now(); time.Since(start) < 60*time.Second; {
		resultURL := fmt.Sprintf("%s/intelligent/search/result?id=%s", i.baseURL, id)
		resp, err := i.client.R().SetContext(ctx).Get(resultURL)
		if err != nil {
			time.Sleep(2 * time.Second)
			continue
		}
		if resp.StatusCode != 200 {
			time.Sleep(2 * time.Second)
			continue
		}
		body := resp.String()
		if !gjson.Valid(body) {
			time.Sleep(2 * time.Second)
			continue
		}
		result := gjson.Parse(body)
		if result.Get("status").Int() == 0 {
			// 成功
			for _, item := range result.Get("selectors").Array() {
				selector := item.Get("selector").String()
				typ := item.Get("type").String()
				asset := models.NewAsset().
					WithTitle(fmt.Sprintf("[IntelX] %s", selector)).
					WithSource(i.Name()).
					WithTags("intelx", typ).
					WithRaw("selector", selector).
					WithRaw("type", typ)
				if strings.Contains(selector, "@") {
					// 邮箱
					asset.WithHost(selector)
				} else if strings.Contains(selector, ".") {
					// 域名
					asset.WithDomain(selector).WithHost(selector)
				}
				allAssets = append(allAssets, asset)
			}
			break
		}
		time.Sleep(2 * time.Second)
	}
	if len(allAssets) > cfg.MaxAssets {
		allAssets = allAssets[:cfg.MaxAssets]
	}
	return allAssets, nil
}
