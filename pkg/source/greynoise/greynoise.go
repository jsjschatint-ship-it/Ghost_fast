package greynoise

import (
	"context"
	"fmt"
	"time"

	"github.com/imroc/req/v3"
	"github.com/tidwall/gjson"
	"github.com/wgpsec/ENScan/pkg/models"
	"github.com/wgpsec/ENScan/pkg/source"
)

// GreyNoise 实现 GreyNoise 威胁情报
type GreyNoise struct {
	*source.BaseSource
	client *req.Client
}

// NewGreyNoise 创建 GreyNoise
func NewGreyNoise() *GreyNoise {
	g := &GreyNoise{
		BaseSource: source.NewBaseSource("greynoise"),
	}
	g.buildClient()
	return g
}

// Name 返回名称
func (g *GreyNoise) Name() string {
	return g.BaseSource.Name()
}

// Accepts 接受的输入类型
func (g *GreyNoise) Accepts() []string {
	return []string{"ip"}
}

// NeedsKey 是否需要 API Key
func (g *GreyNoise) NeedsKey() bool {
	return true
}

// SetKey 设置 API Key
func (g *GreyNoise) SetKey(key string) {
	g.BaseSource.SetKey(key)
	g.buildClient()
}

// SetConfig 设置配置
func (g *GreyNoise) SetConfig(cfg map[string]any) error {
	_ = g.BaseSource.SetConfig(cfg)
	g.buildClient()
	return nil
}

// buildClient 构建 HTTP 客户端
func (g *GreyNoise) buildClient() {
	c := req.C()
	c.SetTimeout(30 * time.Second)
	c.SetUserAgent("Mozilla/5.0 (compatible; Ghost/1.0)")
	if g.BaseSource.Key() != "" {
		c.SetCommonHeader("Key", g.BaseSource.Key())
	}
	g.client = c
}

// Search 执行搜索
func (g *GreyNoise) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	if g.client == nil {
		g.buildClient()
	}
	cfg := &source.SearchConfig{
		MaxAssets: 50,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	// GreyNoise IP 查询
	u := fmt.Sprintf("https://api.greynoise.io/v3/community/%s", target)
	resp, err := g.client.R().SetContext(ctx).Get(u)
	if err != nil {
		return nil, fmt.Errorf("request greynoise: %w", err)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("greynoise api status %d", resp.StatusCode)
	}
	body := resp.String()
	if !gjson.Valid(body) {
		return nil, fmt.Errorf("invalid json")
	}
	data := gjson.Parse(body)
	// 解析威胁情报
	classification := data.Get("classification").String()
	if classification == "malicious" || classification == "suspicious" {
		asset := models.NewAsset().
			WithTitle(fmt.Sprintf("[GreyNoise] %s (%s)", target, classification)).
			WithIP(target).
			WithSource(g.Name()).
			WithTags("malicious", "ip", "greynoise").
			WithRaw("classification", classification).
			WithRaw("confidence", data.Get("confidence").String()).
			WithRaw("last_seen", data.Get("last_seen").String()).
			WithRaw("actor", data.Get("actor").String())
		return []*models.Asset{asset}, nil
	}
	return nil, nil
}
