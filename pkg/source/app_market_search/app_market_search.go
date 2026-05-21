package app_market_search

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

// AppMarketSearch 实现应用商店/小程序搜索
type AppMarketSearch struct {
	*source.BaseSource
	client *req.Client
}

// NewAppMarketSearch 创建 AppMarketSearch
func NewAppMarketSearch() *AppMarketSearch {
	s := &AppMarketSearch{
		BaseSource: source.NewBaseSource("app_market_search"),
	}
	s.buildClient()
	return s
}

// Name 返回名称
func (s *AppMarketSearch) Name() string {
	return s.BaseSource.Name()
}

// Accepts 接受的输入类型
func (s *AppMarketSearch) Accepts() []string {
	return []string{"domain", "company"}
}

// NeedsKey 是否需要 API Key
func (s *AppMarketSearch) NeedsKey() bool {
	return false
}

// SetConfig 设置配置
func (s *AppMarketSearch) SetConfig(cfg map[string]any) error {
	_ = s.BaseSource.SetConfig(cfg)
	s.buildClient()
	return nil
}

// buildClient 构建 HTTP 客户端
func (s *AppMarketSearch) buildClient() {
	c := req.C()
	c.SetTimeout(30 * time.Second)
	c.SetUserAgent("Mozilla/5.0 (compatible; Ghost/1.0)")
	s.client = c
}

// Search 执行搜索
func (s *AppMarketSearch) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	cfg := &source.SearchConfig{
		MaxAssets: 50,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	dorks := s.buildDorks(target)
	var allAssets []*models.Asset
	var mu sync.Mutex
	var wg sync.WaitGroup

	// 限制并发数
	sem := make(chan struct{}, 5)
	for _, dork := range dorks {
		wg.Add(1)
		go func(q string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			// 使用 DuckDuckGo（无需 API Key）
			results, err := s.duckduckgo(ctx, q, 15)
			if err != nil {
				return
			}
			for _, res := range results {
				asset := models.NewAsset().
					WithTitle(fmt.Sprintf("[%s] %s", res.platform, res.title)).
					WithURL(res.url).
					WithSource(s.Name()).
					WithTags("app", "market", res.platform).
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

// buildDorks 构建 dork
func (s *AppMarketSearch) buildDorks(target string) []string {
	platforms := map[string]string{
		"google_play": "play.google.com",
		"app_store":   "apps.apple.com",
		"huawei":      "appgallery.huawei.com",
		"xiaomi":      "app.mi.com",
		"oppo":        "store.oppomobile.com",
		"vivo":        "app.vivo.com.cn",
		"kuan":        "coolapk.com",
		"yingyongbao": "sj.qq.com",
		"wandoujia":   "www.wandoujia.com",
		"360":         "app.360.cn",
		"baidu":       "app.baidu.com",
		"wechat_mp":   "mp.weixin.qq.com",
		"alipay_mp":   "open.alipay.com",
	}
	var dorks []string
	for _, site := range platforms {
		dorks = append(dorks, fmt.Sprintf("site:%s \"%s\"", site, target))
	}
	return dorks
}

// duckduckgo 使用 DuckDuckGo 即时答案 API（无需 key）
func (s *AppMarketSearch) duckduckgo(ctx context.Context, query string, limit int) ([]dorkResult, error) {
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
func (s *AppMarketSearch) detectPlatform(u string) string {
	u = strings.ToLower(u)
	if strings.Contains(u, "play.google.com") {
		return "google_play"
	}
	if strings.Contains(u, "apps.apple.com") {
		return "app_store"
	}
	if strings.Contains(u, "appgallery.huawei.com") {
		return "huawei"
	}
	if strings.Contains(u, "app.mi.com") {
		return "xiaomi"
	}
	if strings.Contains(u, "store.oppomobile.com") {
		return "oppo"
	}
	if strings.Contains(u, "app.vivo.com.cn") {
		return "vivo"
	}
	if strings.Contains(u, "coolapk.com") {
		return "kuan"
	}
	if strings.Contains(u, "sj.qq.com") {
		return "yingyongbao"
	}
	if strings.Contains(u, "www.wandoujia.com") {
		return "wandoujia"
	}
	if strings.Contains(u, "app.360.cn") {
		return "360"
	}
	if strings.Contains(u, "app.baidu.com") {
		return "baidu"
	}
	if strings.Contains(u, "mp.weixin.qq.com") {
		return "wechat_mp"
	}
	if strings.Contains(u, "open.alipay.com") {
		return "alipay_mp"
	}
	return "unknown"
}
