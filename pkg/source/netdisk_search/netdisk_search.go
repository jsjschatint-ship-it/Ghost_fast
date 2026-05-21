//go:build broken_recovery
// +build broken_recovery

package netdisk_search

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/imroc/req/v3"
	"github.com/tidwall/gjson"
	"github.com/wgpsec/ENScan/pkg/models"
	"github.com/wgpsec/ENScan/pkg/source"
)

// NetdiskSearch 实现网盘公开分享搜索
type NetdiskSearch struct {
	*source.BaseSource
	client *req.Client
}

// NewNetdiskSearch 创建 NetdiskSearch
func NewNetdiskSearch() *NetdiskSearch {
	s := &NetdiskSearch{
		BaseSource: source.NewBaseSource("netdisk_search"),
	}
	s.buildClient()
	return s
}

// Name 返回名称
func (s *NetdiskSearch) Name() string {
	return s.BaseSource.Name()
}

// Accepts 接受的输入类型
func (s *NetdiskSearch) Accepts() []string {
	return []string{"domain", "company"}
}

// NeedsKey 是否需要 API Key
func (s *NetdiskSearch) NeedsKey() bool {
	return false
}

// SetConfig 设置配置
func (s *NetdiskSearch) SetConfig(cfg map[string]any) error {
	_ = s.BaseSource.SetConfig(cfg)
	s.buildClient()
	return nil
}

// buildClient 构建 HTTP 客户端
func (s *NetdiskSearch) buildClient() {
	c := req.C()
	c.SetTimeout(30 * time.Second)
	c.SetUserAgent("Mozilla/5.0 (compatible; Ghost/1.0)")
	s.client = c
}

// Search 执行搜索
func (s *NetdiskSearch) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	cfg := &source.SearchConfig{
		MaxAssets: 60,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	// 构建 dork
	dorks := s.buildDorks(target)
	var allAssets []*models.Asset
	var mu sync.Mutex
	var wg sync.WaitGroup

	// 限制并发数
	// 限制并发数
	sem := make(chan struct{}, 5)
	for _, dork := range dorks {
		wg.Add(1)
		go func(q string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			// 使用 DuckDuckGo（无需 API Key）
			// 使用 DuckDuckGo（无需 API Key）
			results, err := s.duckduckgo(ctx, q, 15)
			if err != nil {
				return
			}
			for _, res := range results {
				asset := models.NewAsset().
					WithTitle(fmt.Sprintf("[netdisk] %s", res.title)).
					WithURL(res.url).
					WithSource(s.Name()).
					WithTags("netdisk", "public", res.platform).
					WithRaw("platform", res.platform).
					WithRaw("snippet", res.snippet)
				mu.Lock()
				allAssets = append(allAssets, asset)
				if len(allAssets) >= cfg.MaxAssets {
					mu.Unlock()
					return
				}
				mu.Unlock()
			}
		}(dork)
	}
	wg.Wait()

	if len(allAssets) > cfg.MaxAssets {
		allAssets = allAssets[:cfg.MaxAssets]
	}
	return allAssets, nil
}

type dorkResult struct {
	title    string
	url      string
	snippet  string
	platform string
}

// buildDorks 构建 dork 列表
func (s *NetdiskSearch) buildDorks(target string) []string {
	// 网盘平台关键字
	// 网盘平台关键字
	platforms := []string{
		"百度网盘", "pan.baidu.com", "baidu.com/s/1",
		"阿里云盘", "aliyundrive.com", "alipan.com",
		"蓝奏云", "lanzouo.com", "lanzoux.com",
		"夸克网盘", "quark.cn",
		"天翼云盘", "cloud.189.cn",
		"微云", "weiyun.com",
		"城通网盘", "ctfile.com",
		"迅雷网盘", "xunlei.com",
		"OneDrive", "1drv.ms",
		"Mega", "mega.nz",
		"Dropbox", "dropbox.com",
		"Google Drive", "drive.google.com",
	}
	var dorks []string
	for _, p := range platforms {
		dorks = append(dorks, fmt.Sprintf("site:%s %s", p, target))
	}
	// 可选高敏关键字
	// if extra, ok := cfg.Extra["extra_terms"].([]string); ok {
	// 	for _, term := range extra {
	// 		for _, p := range platforms {
	// 			dorks = append(dorks, fmt.Sprintf("site:%s %s %s", p, target, term))
	// 		}
	// 	}
	// }
	return dorks
}

// duckduckgo 使用 DuckDuckGo 即时答案 API（无需 key）
func (s *NetdiskSearch) duckduckgo(ctx context.Context, query string, limit int) ([]dorkResult, error) {
	u := "https://api.duckduckgo.com/"
	q := url.Values{}
	q.Set("q", query)
	q.Set("format", "json")
	q.Set("no_html", "1")
	q.Set("skip_disambig", "1")
	fullURL := u + "?" + q.Encode()

	resp, err := s.client.R().SetContext(ctx).Get(fullURL)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("duckduckgo api status %d", resp.StatusCode)
	}

	body := resp.String()
	if !gjson.Valid(body) {
		return nil, fmt.Errorf("invalid json")
	}
	data := gjson.Parse(body)
	var results []dorkResult
	// DuckDuckGo 即时答案 API 返回 RelatedTopics
	topics := data.Get("RelatedTopics").Array()
	for i, t := range topics {
		if i >= limit {
			break
		}
		title := t.Get("Text").String()
		link := t.Get("FirstURL").String()
		if title == "" || link == "" {
			continue
		}
		platform := s.detectPlatform(link)
		results = append(results, dorkResult{
			title:    title,
			url:      link,
			snippet:  title,
			platform: platform,
		})
	}
	return results, nil
}

// detectPlatform 检测平台
func (s *NetdiskSearch) detectPlatform(u string) string {
	u = strings.ToLower(u)
	if strings.Contains(u, "baidu.com") || strings.Contains(u, "pan.baidu.com") {
		return "baidu"
	}
	if strings.Contains(u, "aliyundrive.com") || strings.Contains(u, "alipan.com") {
		return "aliyun"
	}
	if strings.Contains(u, "lanzouo.com") || strings.Contains(u, "lanzoux.com") {
		return "lanzou"
	}
	if strings.Contains(u, "quark.cn") {
		return "quark"
	}
	if strings.Contains(u, "cloud.189.cn") {
		return "tianyi"
	}
	if strings.Contains(u, "weiyun.com") {
		return "weiyun"
	}
	if strings.Contains(u, "ctfile.com") {
		return "chengtong"
	}
	if strings.Contains(u, "xunlei.com") {
		return "xunlei"
	}
	if strings.Contains(u, "1drv.ms") || strings.Contains(u, "onedrive.live.com") {
		return "onedrive"
	}
	if strings.Contains(u, "mega.nz") {
		return "mega"
	}
	if strings.Contains(u, "dropbox.com") || strings.Contains(u, "dl.dropboxusercontent.com") {
		return "dropbox"
	}
	if strings.Contains(u, "drive.google.com") {
		return "googledrive"
	}
	return "unknown"
}
