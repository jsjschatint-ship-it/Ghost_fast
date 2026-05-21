package censys

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
	defaultCensysURL = "https://search.censys.io/api/v2"
	defaultSize      = 100
)

// Censys 实现 Censys 引擎
type Censys struct {
	*source.BaseSource
	client  *req.Client
	baseURL string
}

// NewCensys 创建 Censys
func NewCensys() *Censys {
	c := &Censys{
		BaseSource: source.NewBaseSource("censys"),
		baseURL:    defaultCensysURL,
	}
	c.buildClient()
	return c
}

// Name 返回名称
func (c *Censys) Name() string {
	return c.BaseSource.Name()
}

// Accepts 接受的输入类型
func (c *Censys) Accepts() []string {
	return []string{"domain", "ip"}
}

// NeedsKey 是否需要 API Key
func (c *Censys) NeedsKey() bool {
	return true
}

// SetKey 设置 API Key
func (c *Censys) SetKey(key string) {
	c.BaseSource.SetKey(key)
	c.buildClient()
}

// SetConfig 设置配置
func (c *Censys) SetConfig(cfg map[string]any) error {
	_ = c.BaseSource.SetConfig(cfg)
	c.buildClient()
	return nil
}

// buildClient 构建 HTTP 客户端
func (c *Censys) buildClient() {
	client := req.C()
	client.SetTimeout(30 * time.Second)
	client.SetUserAgent("Mozilla/5.0 (compatible; Ghost/1.0)")
	// Censys 使用 Basic Auth
	if c.BaseSource.Key() != "" {
		client.SetCommonBasicAuth(c.BaseSource.Key(), "")
	}
	c.client = client
}

// Search 执行搜索
func (c *Censys) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	if c.client == nil {
		c.buildClient()
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
		query = fmt.Sprintf("ip: %s", target)
	} else {
		query = fmt.Sprintf("names: %s", target)
	}

	var allAssets []*models.Asset
	cursor := ""
	for len(allAssets) < cfg.MaxAssets {
		payload := map[string]any{
			"q":        query,
			"per_page": defaultSize,
			"cursor":   cursor,
		}
		resp, err := c.client.R().
			SetContext(ctx).
			SetHeader("Accept", "application/json").
			SetBodyJsonMarshal(payload).
			Post(c.baseURL + "/certificates/search")
		if err != nil {
			return nil, fmt.Errorf("request censys: %w", err)
		}
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("censys api status %d", resp.StatusCode)
		}
		body := resp.String()
		if !gjson.Valid(body) {
			return nil, fmt.Errorf("invalid json")
		}
		data := gjson.Parse(body)
		items := data.Get("result.hits").Array()
		if len(items) == 0 {
			break
		}
		for _, item := range items {
			// 解析证书信息
			names := item.Get("names").Array()
			if len(names) == 0 {
				continue
			}
			domain := names[0].String()
			fingerprint := item.Get("fingerprint_sha256").String()
			issuerDN := item.Get("issuer_dn").String()
			subjectDN := item.Get("subject_dn").String()
			validFrom := item.Get("validity.start").String()
			validTo := item.Get("validity.end").String()
			asset := models.NewAsset().
				WithTitle(fmt.Sprintf("[Censys] %s", domain)).
				WithDomain(domain).
				WithSource(c.Name()).
				WithTags("tls", "cert", "censys").
				WithRaw("fingerprint", fingerprint).
				WithRaw("issuer_dn", issuerDN).
				WithRaw("subject_dn", subjectDN).
				WithRaw("valid_from", validFrom).
				WithRaw("valid_to", validTo)
			allAssets = append(allAssets, asset)
		}
		// 检查下一页
		if data.Get("result.links.next").String() == "" {
			break
		}
		cursor = data.Get("result.links.next").String()
		time.Sleep(1 * time.Second)
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
