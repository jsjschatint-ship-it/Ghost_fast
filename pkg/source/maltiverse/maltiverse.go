//go:build broken_recovery
// +build broken_recovery

package maltiverse

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
	defaultMaltiverseURL = "https://api.maltiverse.com"
)

// Maltiverse 实现 Maltiverse 威胁情报
type Maltiverse struct {
	*source.BaseSource
	client  *req.Client
	baseURL string
}

// NewMaltiverse 创建 Maltiverse
func NewMaltiverse() *Maltiverse {
	m := &Maltiverse{
		BaseSource: source.NewBaseSource("maltiverse"),
		baseURL:    defaultMaltiverseURL,
	}
	m.buildClient()
	return m
}

// Name 返回名称
func (m *Maltiverse) Name() string {
	return m.BaseSource.Name()
}

// Accepts 接受的输入类型
func (m *Maltiverse) Accepts() []string {
	return []string{"ip", "domain", "hash"}
}

// NeedsKey 是否需要 API Key
func (m *Maltiverse) NeedsKey() bool {
	return false
}

// SetConfig 设置配置
func (m *Maltiverse) SetConfig(cfg map[string]any) error {
	_ = m.BaseSource.SetConfig(cfg)
	m.buildClient()
	return nil
}

// buildClient 构建 HTTP 客户端
func (m *Maltiverse) buildClient() {
	c := req.C()
	c.SetTimeout(30 * time.Second)
	c.SetUserAgent("Mozilla/5.0 (compatible; Ghost/1.0)")
	m.client = c
}

// Search 执行搜索
func (m *Maltiverse) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	cfg := &source.SearchConfig{
		MaxAssets: 50,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	var allAssets []*models.Asset
	// IP 查询
	if isIP(target) {
		if assets, err := m.queryIP(ctx, target); err == nil {
			allAssets = append(allAssets, assets...)
		}
	}
	// 域名查询
	if isDomain(target) {
		if assets, err := m.queryDomain(ctx, target); err == nil {
			allAssets = append(allAssets, assets...)
		}
	}
	// 哈希查询
	if isHash(target) {
		if assets, err := m.queryHash(ctx, target); err == nil {
			allAssets = append(allAssets, assets...)
		}
	}

	if len(allAssets) > cfg.MaxAssets {
		allAssets = allAssets[:cfg.MaxAssets]
	}
	return allAssets, nil
}

// queryIP 查询 IP
func (m *Maltiverse) queryIP(ctx context.Context, ip string) ([]*models.Asset, error) {
	u := fmt.Sprintf("%s/ip/%s", m.baseURL, ip)
	resp, err := m.client.R().SetContext(ctx).Get(u)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("maltiverse ip status %d", resp.StatusCode)
	}
	body := resp.String()
	if !gjson.Valid(body) {
		return nil, fmt.Errorf("invalid json")
	}
	data := gjson.Parse(body)
	// 解析威胁情报
	malicious := data.Get("malicious").Bool()
	if malicious {
		asset := models.NewAsset().
			WithTitle(fmt.Sprintf("[Maltiverse] %s (malicious)", ip)).
			WithIP(ip).
			WithSource(m.Name()).
			WithTags("malicious", "ip", "maltiverse").
			WithRaw("malicious", "true").
			WithRaw("confidence", data.Get("confidence").String()).
			WithRaw("description", data.Get("description").String())
		return []*models.Asset{asset}, nil
	}
	return nil, nil
}

// queryDomain 查询域名
func (m *Maltiverse) queryDomain(ctx context.Context, domain string) ([]*models.Asset, error) {
	u := fmt.Sprintf("%s/domain/%s", m.baseURL, domain)
	resp, err := m.client.R().SetContext(ctx).Get(u)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("maltiverse domain status %d", resp.StatusCode)
	}
	body := resp.String()
	if !gjson.Valid(body) {
		return nil, fmt.Errorf("invalid json")
	}
	data := gjson.Parse(body)
	malicious := data.Get("malicious").Bool()
	if malicious {
		asset := models.NewAsset().
			WithTitle(fmt.Sprintf("[Maltiverse] %s (malicious)", domain)).
			WithDomain(domain).
			WithHost(domain).
			WithSource(m.Name()).
			WithTags("malicious", "domain", "maltiverse").
			WithRaw("malicious", "true").
			WithRaw("confidence", data.Get("confidence").String()).
			WithRaw("description", data.Get("description").String())
		return []*models.Asset{asset}, nil
	}
	return nil, nil
}

// queryHash 查询哈希
func (m *Maltiverse) queryHash(ctx context.Context, hash string) ([]*models.Asset, error) {
	u := fmt.Sprintf("%s/hash/%s", m.baseURL, hash)
	resp, err := m.client.R().SetContext(ctx).Get(u)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("maltiverse hash status %d", resp.StatusCode)
	}
	body := resp.String()
	if !gjson.Valid(body) {
		return nil, fmt.Errorf("invalid json")
	}
	data := gjson.Parse(body)
	malicious := data.Get("malicious").Bool()
	if malicious {
		asset := models.NewAsset().
			WithTitle(fmt.Sprintf("[Maltiverse] %s (malicious)", hash)).
			WithSource(m.Name()).
			WithTags("malicious", "hash", "maltiverse").
			WithRaw("hash", hash).
			WithRaw("malicious", "true").
			WithRaw("confidence", data.Get("confidence").String()).
			WithRaw("description", data.Get("description").String())
		return []*models.Asset{asset}, nil
	}
	return nil, nil
}

// 辅助函数
func isIP(s string) bool {
	// 简化实现，实际可用 net.ParseIP
	return strings.Contains(s, ".")
}

func isDomain(s string) bool {
	return !isIP(s) && !isHash(s)
}

func isHash(s string) bool {
	// 简单判断：32/40/64 位十六进制
	// 简单判断：32/40/64 位十六进制
	return len(s) == 32 || len(s) == 40 || len(s) == 64
}
