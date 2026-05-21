//go:build broken_recovery
// +build broken_recovery

package source_map_leak

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/imroc/req/v3"
	"github.com/wgpsec/ENScan/pkg/models"
	"github.com/wgpsec/ENScan/pkg/source"
	wb "github.com/wgpsec/ENScan/pkg/source/internal/wayback"
)

// SourceMapLeak 实现 JS Source Map 泄露检测
type SourceMapLeak struct {
	*source.BaseSource
	client *req.Client
}

// NewSourceMapLeak 创建 SourceMapLeak
func NewSourceMapLeak() *SourceMapLeak {
	s := &SourceMapLeak{
		BaseSource: source.NewBaseSource("source_map_leak"),
	}
	s.buildClient()
	return s
}

// Name 返回名称
func (s *SourceMapLeak) Name() string {
	return s.BaseSource.Name()
}

// Accepts 接受的输入类型
func (s *SourceMapLeak) Accepts() []string {
	return []string{"domain", "url"}
}

// NeedsKey 是否需要 API Key
func (s *SourceMapLeak) NeedsKey() bool {
	return false
}

// SetConfig 设置配置
func (s *SourceMapLeak) SetConfig(cfg map[string]any) error {
	_ = s.BaseSource.SetConfig(cfg)
	s.buildClient()
	return nil
}

// buildClient 构建 HTTP 客户端
func (s *SourceMapLeak) buildClient() {
	c := req.C()
	c.SetTimeout(30 * time.Second) // 30s
	c.SetUserAgent("Mozilla/5.0 (compatible; Ghost/1.0)")
	s.client = c
}

// Search 执行搜索
func (s *SourceMapLeak) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	cfg := &source.SearchConfig{
		MaxAssets: 200,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	// 输入：cfg.Extra["js_urls"] 由上游注入；或者 target 本身是 URL
	var jsAssets []string
	if cfg.Extra != nil {
		if v, ok := cfg.Extra["js_urls"].([]string); ok {
			jsAssets = append(jsAssets, v...)
		} else if v, ok := cfg.Extra["js_urls"].([]any); ok {
			for _, x := range v {
				if str, ok2 := x.(string); ok2 {
					jsAssets = append(jsAssets, str)
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

	// 默认零流量到目标：通过 Wayback 查询 .js.map 是否有历史快照。
	// cfg.Extra["direct_fetch"] = true 时才直连目标做 HEAD/GET（主动模式）
	directFetch := false
	if cfg.Extra != nil {
		if v, ok := cfg.Extra["direct_fetch"].(bool); ok {
			directFetch = v
		}
	}

	for _, jsURL := range jsAssets {
		wg.Add(1)
		go func(js string) {
			defer wg.Done()
			mapURL := s.deriveMapURL(js)
			if mapURL == "" {
				return
			}
			fetchURL := mapURL
			via := "direct"
			if !directFetch {
				snap, err := wb.SnapshotURL(ctx, s.client, mapURL, true)
				if err != nil || snap == "" {
					// archive.org 无快照：被动模式下放弃，绝不触碰目标
					return
				}
				fetchURL = snap
				via = "wayback"
			} else {
				// 直连：先 HEAD 看在不在
				resp, err := s.client.R().SetContext(ctx).Head(mapURL)
				if err != nil || resp.StatusCode != 200 {
					return
				}
			}
			resp, err := s.client.R().SetContext(ctx).Get(fetchURL)
			if err != nil || resp.StatusCode != 200 {
				return
			}
			body := resp.String()
			sources := s.extractSources(body)
			asset := models.NewAsset().
				WithTitle(fmt.Sprintf("[source_map] %s", mapURL)).
				WithURL(mapURL).
				WithSource(s.Name()).
				WithTags("frontend", "sourcemap", "leak", "via:"+via).
				WithRaw("js_url", js).
				WithRaw("snapshot", fetchURL).
				WithRaw("via", via).
				WithRaw("sources", strings.Join(sources, ","))
			mu.Lock()
			allAssets = append(allAssets, asset)
			mu.Unlock()
		}(jsURL)
	}
	wg.Wait()

	if len(allAssets) > cfg.MaxAssets {
		allAssets = allAssets[:cfg.MaxAssets]
	}
	return allAssets, nil
}

// deriveMapURL 从 JS URL 派生可能的 .js.map URL
func (s *SourceMapLeak) deriveMapURL(jsURL string) string {
	u, err := url.Parse(jsURL)
	if err != nil {
		return ""
	}
	// 常见模式：
	// 1) 同目录同文件名 + .map
	// 2) 同目录原文件名 + .map
	// 3) ./maps/xxx.js.map
	base := u.Path
	if strings.HasSuffix(base, ".js") {
		base = base[:len(base)-3]
	}
	// 尝试 1: 同目录
	candidate1 := u.Scheme + "://" + u.Host + base + ".js.map"
	// 尝试 2: maps 子目录（预留备选）
	_ = base
	// 简单返回第一个
	return candidate1
}

// extractSources 从 source map 内容提取 sources 字段
func (s *SourceMapLeak) extractSources(body string) []string {
	// 简单正则提取 "sources": [...]
	re := regexp.MustCompile(`"sources":\s*\[([^\]]+)\]`)
	m := re.FindStringSubmatch(body)
	if len(m) < 2 {
		return nil
	}
	srcs := strings.Split(m[1], ",")
	var out []string
	for _, src := range srcs {
		src = strings.Trim(src, ` "`)
		if src != "" {
			out = append(out, src)
		}
	}
	return out
}
