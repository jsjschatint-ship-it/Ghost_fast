//go:build broken_recovery
// +build broken_recovery

package employee_dork

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

// EmployeeDork 实现员工/组织信息搜索
type EmployeeDork struct {
	*source.BaseSource
	client *req.Client
}

// NewEmployeeDork 创建 EmployeeDork
func NewEmployeeDork() *EmployeeDork {
	s := &EmployeeDork{
		BaseSource: source.NewBaseSource("employee_dork"),
	}
	s.buildClient()
	return s
}

// Name 返回名称
func (s *EmployeeDork) Name() string {
	return s.BaseSource.Name()
}

// Accepts 接受的输入类型
func (s *EmployeeDork) Accepts() []string {
	return []string{"domain", "company"}
}

// NeedsKey 是否需要 API Key
func (s *EmployeeDork) NeedsKey() bool {
	return false
}

// SetConfig 设置配置
func (s *EmployeeDork) SetConfig(cfg map[string]any) error {
	_ = s.BaseSource.SetConfig(cfg)
	s.buildClient()
	return nil
}

// buildClient 构建 HTTP 客户端
func (s *EmployeeDork) buildClient() {
	c := req.C()
	c.SetTimeout(30 * time.Second)
	c.SetUserAgent("Mozilla/5.0 (compatible; Ghost/1.0)")
	s.client = c
}

// Search 执行搜索
func (s *EmployeeDork) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	cfg := &source.SearchConfig{
		MaxAssets: 60,
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
					WithTags("employee", "info", res.platform).
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
func (s *EmployeeDork) buildDorks(target string) []string {
	platforms := map[string][]string{
		"linkedin":    {"linkedin.com/in OR linkedin.com/pub"},
		"linkedin_co": {"linkedin.com/company"},
		"maimai":      {"maimai.cn"},
		"kanzhun":     {"kanzhun.com"},
		"boss":        {"zhipin.com"},
		"lagou":       {"lagou.com"},
		"zhilian":     {"zhaopin.com"},
		"51job":       {"51job.com"},
		"liepin":      {"liepin.com"},
		"github_org":  {"github.com/orgs"},
		"zhihu":       {"zhihu.com"},
		"v2ex":        {"v2ex.com"},
		"qichacha":    {"qcc.com OR qichacha.com"},
		"tianyancha":  {"tianyancha.com"},
		"aiqicha":     {"aiqicha.baidu.com"},
	}
	var dorks []string
	for pid, sites := range platforms {
		for _, site := range sites {
			dorks = append(dorks, fmt.Sprintf("site:%s \"%s\"", site, target))
			// 细化关键字
			switch {
			case pid == "boss" || pid == "lagou" || pid == "zhilian" || pid == "51job" || pid == "liepin":
				dorks = append(dorks, fmt.Sprintf("site:%s \"%s\" (架构师 OR 高级 OR DBA OR 安全 OR 运维)", site, target))
			case strings.HasSuffix(pid, "_equity"):
				dorks = append(dorks, fmt.Sprintf("site:%s \"%s\" (股权结构 OR 股东 OR 持股比例)", site, target))
			case strings.HasSuffix(pid, "_invest"):
				dorks = append(dorks, fmt.Sprintf("site:%s \"%s\" (对外投资 OR 控股 OR 子公司)", site, target))
			case strings.HasSuffix(pid, "_software"):
				dorks = append(dorks, fmt.Sprintf("site:%s \"%s\" (软件著作权 OR 软件登记)", site, target))
			case strings.HasSuffix(pid, "_app"):
				dorks = append(dorks, fmt.Sprintf("site:%s \"%s\" (APP备案 OR 应用备案 OR 移动应用)", site, target))
			case strings.HasSuffix(pid, "_mp"):
				dorks = append(dorks, fmt.Sprintf("site:%s \"%s\" (小程序 OR 公众号 OR 微信)", site, target))
			}
		}
	}
	return dorks
}

// duckduckgo 使用 DuckDuckGo 即时答案 API（无需 key）
func (s *EmployeeDork) duckduckgo(ctx context.Context, query string, limit int) ([]dorkResult, error) {
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
func (s *EmployeeDork) detectPlatform(u string) string {
	u = strings.ToLower(u)
	if strings.Contains(u, "linkedin.com") {
		return "linkedin"
	}
	if strings.Contains(u, "maimai.cn") {
		return "maimai"
	}
	if strings.Contains(u, "kanzhun.com") {
		return "kanzhun"
	}
	if strings.Contains(u, "zhipin.com") {
		return "boss"
	}
	if strings.Contains(u, "lagou.com") {
		return "lagou"
	}
	if strings.Contains(u, "zhaopin.com") {
		return "zhilian"
	}
	if strings.Contains(u, "51job.com") {
		return "51job"
	}
	if strings.Contains(u, "liepin.com") {
		return "liepin"
	}
	if strings.Contains(u, "github.com") {
		return "github"
	}
	if strings.Contains(u, "zhihu.com") {
		return "zhihu"
	}
	if strings.Contains(u, "v2ex.com") {
		return "v2ex"
	}
	if strings.Contains(u, "qcc.com") || strings.Contains(u, "qichacha.com") {
		return "qichacha"
	}
	if strings.Contains(u, "tianyancha.com") {
		return "tianyancha"
	}
	if strings.Contains(u, "aiqicha.baidu.com") {
		return "aiqicha"
	}
	return "unknown"
}
