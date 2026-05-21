package cve_match

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

// CVEMatch 实现 CVE 漏洞匹配
type CVEMatch struct {
	*source.BaseSource
	client *req.Client
}

// NewCVEMatch 创建 CVEMatch
func NewCVEMatch() *CVEMatch {
	c := &CVEMatch{
		BaseSource: source.NewBaseSource("cve_match"),
	}
	c.buildClient()
	return c
}

// Name 返回名称
func (c *CVEMatch) Name() string {
	return c.BaseSource.Name()
}

// Accepts 接受的输入类型
func (c *CVEMatch) Accepts() []string {
	return []string{"service", "product", "version"}
}

// NeedsKey 是否需要 API Key
func (c *CVEMatch) NeedsKey() bool {
	return false
}

// SetConfig 设置配置
func (c *CVEMatch) SetConfig(cfg map[string]any) error {
	_ = c.BaseSource.SetConfig(cfg)
	c.buildClient()
	return nil
}

// buildClient 构建 HTTP 客户端
func (c *CVEMatch) buildClient() {
	client := req.C()
	client.SetTimeout(30 * time.Second)
	client.SetUserAgent("Mozilla/5.0 (compatible; Ghost/1.0)")
	c.client = client
}

// Search 执行搜索
func (c *CVEMatch) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	cfg := &source.SearchConfig{
		MaxAssets: 50,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	var allAssets []*models.Asset
	// CVE Search API
	if assets, err := c.queryCVE(ctx, target); err == nil {
		allAssets = append(allAssets, assets...)
	}
	// NVD API
	if assets, err := c.queryNVD(ctx, target); err == nil {
		allAssets = append(allAssets, assets...)
	}

	if len(allAssets) > cfg.MaxAssets {
		allAssets = allAssets[:cfg.MaxAssets]
	}
	return allAssets, nil
}

// queryCVE 查询 CVE Search
func (c *CVEMatch) queryCVE(ctx context.Context, target string) ([]*models.Asset, error) {
	// 使用 CIRCL CVE Search 公开 API
	u := fmt.Sprintf("https://cve.circl.lu/api/search/%s", url.QueryEscape(target))
	resp, err := c.client.R().SetContext(ctx).Get(u)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("cve search status %d", resp.StatusCode)
	}
	body := resp.String()
	if !gjson.Valid(body) {
		return nil, fmt.Errorf("invalid json")
	}
	data := gjson.Parse(body)
	var assets []*models.Asset
	for _, item := range data.Get("data").Array() {
		cveID := item.Get("id").String()
		summary := item.Get("summary").String()
		published := item.Get("Published").String()
		cvss := item.Get("cvss").String()
		asset := models.NewAsset().
			WithTitle(fmt.Sprintf("[CVE] %s (%s)", cveID, summary)).
			WithSource(c.Name()).
			WithTags("cve", "vulnerability").
			WithRaw("cve_id", cveID).
			WithRaw("summary", summary).
			WithRaw("published", published).
			WithRaw("cvss", cvss)
		assets = append(assets, asset)
	}
	return assets, nil
}

// queryNVD 查询 NVD API
func (c *CVEMatch) queryNVD(ctx context.Context, target string) ([]*models.Asset, error) {
	// 使用 NVD REST API（legacy v1.0，稳定）
	u := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/1.0?keywordSearch=%s", url.QueryEscape(target))
	resp, err := c.client.R().SetContext(ctx).Get(u)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("nvd api status %d", resp.StatusCode)
	}
	body := resp.String()
	if !gjson.Valid(body) {
		return nil, fmt.Errorf("invalid json")
	}
	data := gjson.Parse(body)
	var assets []*models.Asset
	for _, item := range data.Get("vulnerabilities").Array() {
		cve := item.Get("cve")
		cveID := cve.Get("id").String()
		summary := cve.Get("descriptions.0.value").String()
		published := cve.Get("published").String()
		cvss := cve.Get("metrics.cvssV3.baseScore").String()
		asset := models.NewAsset().
			WithTitle(fmt.Sprintf("[NVD] %s (%s)", cveID, summary)).
			WithSource(c.Name()).
			WithTags("nvd", "vulnerability").
			WithRaw("cve_id", cveID).
			WithRaw("summary", summary).
			WithRaw("published", published).
			WithRaw("cvss", cvss)
		assets = append(assets, asset)
	}
	return assets, nil
}
