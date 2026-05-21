package js_endpoints

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/imroc/req/v3"
	"github.com/wgpsec/ENScan/pkg/models"
	"github.com/wgpsec/ENScan/pkg/source"
	wb "github.com/wgpsec/ENScan/pkg/source/internal/wayback"
)

// JSEndpoints 实现 JS 端点发现
type JSEndpoints struct {
	*source.BaseSource
	client *req.Client
}

// NewJSEndpoints 创建 JSEndpoints
func NewJSEndpoints() *JSEndpoints {
	j := &JSEndpoints{
		BaseSource: source.NewBaseSource("js_endpoints"),
	}
	j.buildClient()
	return j
}

// Name 返回名称
func (j *JSEndpoints) Name() string {
	return j.BaseSource.Name()
}

// Accepts 接受的输入类型
func (j *JSEndpoints) Accepts() []string {
	return []string{"domain", "url"}
}

// NeedsKey 是否需要 API Key
func (j *JSEndpoints) NeedsKey() bool {
	return false
}

// SetConfig 设置配置
func (j *JSEndpoints) SetConfig(cfg map[string]any) error {
	_ = j.BaseSource.SetConfig(cfg)
	j.buildClient()
	return nil
}

// buildClient 构建 HTTP 客户端
func (j *JSEndpoints) buildClient() {
	c := req.C()
	c.SetTimeout(30 * time.Second)
	c.SetUserAgent("Mozilla/5.0 (compatible; Ghost/1.0)")
	j.client = c
}

// Search 执行搜索
func (j *JSEndpoints) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	cfg := &source.SearchConfig{
		MaxAssets: 100,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	// 输入：cfg.Extra["js_urls"] 由上游注入；或者 target 本身是 .js URL
	var jsAssets []string
	if cfg.Extra != nil {
		if v, ok := cfg.Extra["js_urls"].([]string); ok {
			jsAssets = append(jsAssets, v...)
		} else if v, ok := cfg.Extra["js_urls"].([]any); ok {
			for _, x := range v {
				if s, ok2 := x.(string); ok2 {
					jsAssets = append(jsAssets, s)
				}
			}
		}
	}
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		jsAssets = append(jsAssets, target)
	}
	if len(jsAssets) == 0 {
		return nil, nil
	}
	var allAssets []*models.Asset
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, jsURL := range jsAssets {
		wg.Add(1)
		go func(js string) {
			defer wg.Done()
			assets, err := j.extractEndpoints(ctx, js, cfg)
			if err == nil {
				mu.Lock()
				allAssets = append(allAssets, assets...)
				mu.Unlock()
			}
		}(jsURL)
	}
	wg.Wait()

	if len(allAssets) > cfg.MaxAssets {
		allAssets = allAssets[:cfg.MaxAssets]
	}
	return allAssets, nil
}

// extractEndpoints 从 JS 提取端点。
// 默认零流量到目标：通过 Wayback Machine 取最新缓存副本；
// 仅当 cfg.Extra["direct_fetch"] == true 时才直连 jsURL。
func (j *JSEndpoints) extractEndpoints(ctx context.Context, jsURL string, cfg *source.SearchConfig) ([]*models.Asset, error) {
	directFetch := false
	if cfg.Extra != nil {
		if v, ok := cfg.Extra["direct_fetch"].(bool); ok {
			directFetch = v
		}
	}
	fetchURL := jsURL
	via := "direct"
	if !directFetch {
		snap, err := wb.SnapshotURL(ctx, j.client, jsURL, true)
		if err != nil {
			return nil, fmt.Errorf("wayback resolve: %w", err)
		}
		if snap == "" {
			// archive.org 没有快照：被动模式下直接放弃，避免触碰目标
			return nil, nil
		}
		fetchURL = snap
		via = "wayback"
	}
	resp, err := j.client.R().SetContext(ctx).Get(fetchURL)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("fetch js status %d", resp.StatusCode)
	}
	body := resp.String()
	var assets []*models.Asset

	// 提取 API 端点
	apiPatterns := []*regexp.Regexp{
		regexp.MustCompile(`["']?/api/[^"'\s]+["']?`),
		regexp.MustCompile(`["']?/v\d+/[^"'\s]+["']?`),
		regexp.MustCompile(`["']?(?:https?://[^/]+)/api/[^"'\s]+["']?`),
	}
	for _, re := range apiPatterns {
		for _, m := range re.FindAllString(body, -1) {
			m = strings.Trim(m, `"'`)
			asset := models.NewAsset().
				WithTitle(fmt.Sprintf("[JS API] %s", m)).
				WithURL(m).
				WithSource(j.Name()).
				WithTags("js", "api", "endpoint", "via:"+via).
				WithRaw("js_url", jsURL).
				WithRaw("type", "api").
				WithRaw("via", via)
			assets = append(assets, asset)
		}
	}

	// 提取 WebSocket 端点
	wsPatterns := []*regexp.Regexp{
		regexp.MustCompile(`["']?wss?://[^"'\s]+["']?`),
		regexp.MustCompile(`["']?/ws/[^"'\s]+["']?`),
		regexp.MustCompile(`["']?/socket\.io/[^"'\s]+["']?`),
	}
	for _, re := range wsPatterns {
		for _, m := range re.FindAllString(body, -1) {
			m = strings.Trim(m, `"'`)
			asset := models.NewAsset().
				WithTitle(fmt.Sprintf("[JS WebSocket] %s", m)).
				WithURL(m).
				WithSource(j.Name()).
				WithTags("js", "websocket", "endpoint", "via:"+via).
				WithRaw("js_url", jsURL).
				WithRaw("type", "websocket").
				WithRaw("via", via)
			assets = append(assets, asset)
		}
	}

	return assets, nil
}
