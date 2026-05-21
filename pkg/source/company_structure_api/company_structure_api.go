//go:build broken_recovery
// +build broken_recovery

package company_structure_api

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/imroc/req/v3"
	"github.com/tidwall/gjson"
	"github.com/wgpsec/ENScan/pkg/models"
	"github.com/wgpsec/ENScan/pkg/source"
)

// CompanyStructureAPI 瀹炵幇 ENScan_GO MCP 瀹㈡埛绔?
type CompanyStructureAPI struct {
	*source.BaseSource
	client *req.Client
}

// NewCompanyStructureAPI 创建 CompanyStructureAPI
func NewCompanyStructureAPI() *CompanyStructureAPI {
	s := &CompanyStructureAPI{
		BaseSource: source.NewBaseSource("company_structure_api"),
	}
	s.buildClient()
	return s
}

// Name 返回名称
func (s *CompanyStructureAPI) Name() string {
	return s.BaseSource.Name()
}

// Accepts 接受的输入类型
func (s *CompanyStructureAPI) Accepts() []string {
	return []string{"company"}
}

// NeedsKey 是否需要 API Key
func (s *CompanyStructureAPI) NeedsKey() bool {
	return false
}

// SetConfig 设置配置
func (s *CompanyStructureAPI) SetConfig(cfg map[string]any) error {
	_ = s.BaseSource.SetConfig(cfg)
	s.buildClient()
	return nil
}

// buildClient 构建 HTTP 客户端
func (s *CompanyStructureAPI) buildClient() {
	c := req.C()
	c.SetTimeout(60 * time.Second) // 60s
	c.SetUserAgent("Ghost-Go/1.0")
	s.client = c
}

// Search 执行搜索
func (s *CompanyStructureAPI) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	cfg := &source.SearchConfig{
		MaxAssets: 500,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	// 从配置读取 MCP 端点
	endpoint := "http://localhost:8080/api"
	if ep, ok := cfg.Extra["enscan_endpoint"].(string); ok && ep != "" {
		endpoint = ep
	}

	// 构造请求参数
	payload := map[string]any{
		"keyword": target,
		"type":    s.mapTypes(cfg.Extra),
		"field":   s.mapFields(cfg.Extra),
		"invest":  s.mapInvest(cfg.Extra),
	}

	// 发送请求
	resp, err := s.client.R().
		SetContext(ctx).
		SetHeader("Content-Type", "application/json").
		SetBodyJsonMarshal(payload).
		Post(endpoint)
	if err != nil {
		return nil, fmt.Errorf("request Ghost mcp: %w", err)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("Ghost mcp status %d", resp.StatusCode)
	}

	body := resp.String()
	if !gjson.Valid(body) {
		return nil, fmt.Errorf("invalid json from Ghost mcp")
	}
	data := gjson.Parse(body)

	var allAssets []*models.Asset
	var mu sync.Mutex
	var wg sync.WaitGroup

	// 解析企业信息
	if enterprise := data.Get("enterprise_info"); enterprise.Exists() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			assets := s.parseEnterpriseInfo(enterprise.Array())
			mu.Lock()
			allAssets = append(allAssets, assets...)
			mu.Unlock()
		}()
	}

	// 解析控股公司/对外投资
	if investment := data.Get("investment_info"); investment.Exists() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			assets := s.parseInvestmentInfo(investment.Array())
			mu.Lock()
			allAssets = append(allAssets, assets...)
			mu.Unlock()
		}()
	}

	// 解析 ICP 备案
	if icp := data.Get("icp_info"); icp.Exists() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			assets := s.parseICPInfo(icp.Array())
			mu.Lock()
			allAssets = append(allAssets, assets...)
			mu.Unlock()
		}()
	}

	// 解析 APP
	if app := data.Get("app_info"); app.Exists() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			assets := s.parseAppInfo(app.Array())
			mu.Lock()
			allAssets = append(allAssets, assets...)
			mu.Unlock()
		}()
	}

	// 解析微信公众号/小程序
	if wechat := data.Get("wechat_info"); wechat.Exists() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			assets := s.parseWechatInfo(wechat.Array())
			mu.Lock()
			allAssets = append(allAssets, assets...)
			mu.Unlock()
		}()
	}

	wg.Wait()

	if len(allAssets) > cfg.MaxAssets {
		allAssets = allAssets[:cfg.MaxAssets]
	}
	return allAssets, nil
}

// mapTypes 映射数据源
func (s *CompanyStructureAPI) mapTypes(extra map[string]any) string {
	if typ, ok := extra["type"].(string); ok && typ != "" {
		return typ
	}
	return "aqc,tyc" // 默认爱企查/天眼查
}

// mapFields 映射字段
func (s *CompanyStructureAPI) mapFields(extra map[string]any) string {
	if fields, ok := extra["field"].(string); ok && fields != "" {
		return fields
	}
	return "icp,app,wechat"
}

// mapInvest 映射股权比例
func (s *CompanyStructureAPI) mapInvest(extra map[string]any) int {
	if invest, ok := extra["invest"].(int); ok {
		return invest
	}
	if invest, ok := extra["invest"].(float64); ok {
		return int(invest)
	}
	return 100 // 默认 100%
}

// parseEnterpriseInfo 解析企业信息（官网域名）
func (s *CompanyStructureAPI) parseEnterpriseInfo(list []gjson.Result) []*models.Asset {
	var assets []*models.Asset
	for _, item := range list {
		name := item.Get("name").String()
		website := item.Get("website").String()
		if website != "" {
			// 简单提取域名
			host := s.extractHost(website)
			asset := models.NewAsset().
				WithTitle(fmt.Sprintf("[官网] %s", host)).
				WithHost(host).
				WithDomain(host).
				WithSource(s.Name()).
				WithTags("company", "website").
				WithRaw("company", name).
				WithRaw("website", website)
			assets = append(assets, asset)
		}
	}
	return assets
}

// parseInvestmentInfo 解析控股/对外投资信息
func (s *CompanyStructureAPI) parseInvestmentInfo(list []gjson.Result) []*models.Asset {
	var assets []*models.Asset
	for _, item := range list {
		name := item.Get("name").String()
		ratio := item.Get("share_ratio").Float()
		asset := models.NewAsset().
			WithTitle(fmt.Sprintf("[控股] %s (%.1f%%)", name, ratio)).
			WithSource(s.Name()).
			WithTags("company", "investment").
			WithRaw("name", name).
			WithRaw("share_ratio", fmt.Sprintf("%.1f%%", ratio))
		assets = append(assets, asset)
	}
	return assets
}

// parseICPInfo 解析 ICP 备案
func (s *CompanyStructureAPI) parseICPInfo(list []gjson.Result) []*models.Asset {
	var assets []*models.Asset
	for _, item := range list {
		domain := item.Get("domain").String()
		icpNum := item.Get("icp_num").String()
		asset := models.NewAsset().
			WithTitle(fmt.Sprintf("[ICP] %s", domain)).
			WithHost(domain).
			WithDomain(domain).
			WithSource(s.Name()).
			WithTags("icp", "备案").
			WithRaw("icp_num", icpNum)
		assets = append(assets, asset)
	}
	return assets
}

// parseAppInfo 解析 APP
func (s *CompanyStructureAPI) parseAppInfo(list []gjson.Result) []*models.Asset {
	var assets []*models.Asset
	for _, item := range list {
		name := item.Get("name").String()
		platform := item.Get("platform").String()
		asset := models.NewAsset().
			WithTitle(fmt.Sprintf("[APP] %s", name)).
			WithSource(s.Name()).
			WithTags("app", "mobile").
			WithRaw("platform", platform).
			WithRaw("app_name", name)
		assets = append(assets, asset)
	}
	return assets
}

// parseWechatInfo 解析微信公众号/小程序
func (s *CompanyStructureAPI) parseWechatInfo(list []gjson.Result) []*models.Asset {
	var assets []*models.Asset
	for _, item := range list {
		name := item.Get("name").String()
		typ := item.Get("type").String() // 公众号/小程序
		asset := models.NewAsset().
			WithTitle(fmt.Sprintf("[%s] %s", typ, name)).
			WithSource(s.Name()).
			WithTags("wechat", typ).
			WithRaw("type", typ).
			WithRaw("name", name)
		assets = append(assets, asset)
	}
	return assets
}

// extractHost 从 URL 提取 host
func (s *CompanyStructureAPI) extractHost(raw string) string {
	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		parts := strings.Split(raw, "/")
		if len(parts) >= 3 {
			return parts[2]
		}
	}
	return raw
}
