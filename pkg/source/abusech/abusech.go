//go:build broken_recovery
// +build broken_recovery

package abusech

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/imroc/req/v3"
	"github.com/wgpsec/ENScan/pkg/models"
	"github.com/wgpsec/ENScan/pkg/source"
)

// AbuseCH 实现 Abuse.ch 查询（Feodo Tracker、AbuseIPDB 等）
type AbuseCH struct {
	*source.BaseSource
	client *req.Client
}

// NewAbuseCH 创建 AbuseCH
func NewAbuseCH() *AbuseCH {
	s := &AbuseCH{
		BaseSource: source.NewBaseSource("abusech"),
	}
	s.buildClient()
	return s
}

// Name 返回名称
func (s *AbuseCH) Name() string {
	return s.BaseSource.Name()
}

// Accepts 接受的输入类型
func (s *AbuseCH) Accepts() []string {
	return []string{"ip", "domain"}
}

// NeedsKey 是否需要 API Key
func (s *AbuseCH) NeedsKey() bool {
	return false
}

// SetConfig 设置配置
func (s *AbuseCH) SetConfig(cfg map[string]any) error {
	_ = s.BaseSource.SetConfig(cfg)
	s.buildClient()
	return nil
}

// buildClient 构建 HTTP 客户端
func (s *AbuseCH) buildClient() {
	c := req.C()
	c.SetTimeout(30 * time.Second)
	c.SetUserAgent("Mozilla/5.0 (compatible; Ghost/1.0)")
	s.client = c
}

// Search 执行搜索
func (s *AbuseCH) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	cfg := &source.SearchConfig{
		MaxAssets: 50,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	var allAssets []*models.Asset
	// Feodo Tracker
	if assets, err := s.queryFeodo(ctx, target); err == nil {
		allAssets = append(allAssets, assets...)
	}
	// AbuseIPDB
	if assets, err := s.queryAbuseIPDB(ctx, target); err == nil {
		allAssets = append(allAssets, assets...)
	}
	// URLhaus
	if assets, err := s.queryURLhaus(ctx, target); err == nil {
		allAssets = append(allAssets, assets...)
	}

	if len(allAssets) > cfg.MaxAssets {
		allAssets = allAssets[:cfg.MaxAssets]
	}
	return allAssets, nil
}

// queryFeodo 查询 Feodo Tracker
func (s *AbuseCH) queryFeodo(ctx context.Context, target string) ([]*models.Asset, error) {
	u := "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt"
	resp, err := s.client.R().SetContext(ctx).Get(u)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("feodo tracker status %d", resp.StatusCode)
	}
	lines := strings.Split(resp.String(), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Contains(line, target) {
			asset := models.NewAsset().
				WithTitle(fmt.Sprintf("[Feodo] %s", line)).
				WithIP(line).
				WithSource(s.Name()).
				WithTags("malware", "c2", "feodo").
				WithRaw("blocklist", "feodo")
			return []*models.Asset{asset}, nil
		}
	}
	return nil, nil
}

// queryAbuseIPDB 查询 AbuseIPDB（需 API Key，这里仅示例）
func (s *AbuseCH) queryAbuseIPDB(ctx context.Context, target string) ([]*models.Asset, error) {
	u := fmt.Sprintf("https://api.abuseipdb.com/api/v2/check?ip=%s", target)
	resp, err := s.client.R().
		SetContext(ctx).
		SetHeader("Accept", "application/json").
		SetHeader("Key", "").
		Get(u)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("abuseipdb status %d", resp.StatusCode)
	}
	var data map[string]any
	if err := json.Unmarshal(resp.Bytes(), &data); err != nil {
		return nil, fmt.Errorf("invalid json")
	}
	if abuseConfidence, ok := data["data"].(map[string]any)["abuse_confidence_percentage"].(float64); ok && abuseConfidence > 0 {
		asset := models.NewAsset().
			WithTitle(fmt.Sprintf("[AbuseIPDB] %s (%.1f%%)", target, abuseConfidence)).
			WithIP(target).
			WithSource(s.Name()).
			WithTags("malicious", "abuseipdb").
			WithRaw("confidence", fmt.Sprintf("%.1f%%", abuseConfidence))
		return []*models.Asset{asset}, nil
	}
	return nil, nil
}

// queryURLhaus 查询 URLhaus
func (s *AbuseCH) queryURLhaus(ctx context.Context, target string) ([]*models.Asset, error) {
	u := "https://urlhaus.abuse.ch/downloads/urlhaus.txt"
	resp, err := s.client.R().SetContext(ctx).Get(u)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("urlhaus status %d", resp.StatusCode)
	}
	lines := strings.Split(resp.String(), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Contains(line, target) {
			asset := models.NewAsset().
				WithTitle(fmt.Sprintf("[URLhaus] %s", line)).
				WithURL(line).
				WithSource(s.Name()).
				WithTags("malware", "urlhaus").
				WithRaw("blocklist", "urlhaus")
			return []*models.Asset{asset}, nil
		}
	}
	return nil, nil
}
