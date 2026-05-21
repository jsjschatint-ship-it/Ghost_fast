package ci_secret_search

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

// CISecretSearch 实现 CI/CD 公开仓库敏感文件搜索
type CISecretSearch struct {
	*source.BaseSource
	client *req.Client
}

// NewCISecretSearch 创建 CISecretSearch
func NewCISecretSearch() *CISecretSearch {
	s := &CISecretSearch{
		BaseSource: source.NewBaseSource("ci_secret_search"),
	}
	s.buildClient()
	return s
}

// Name 返回名称
func (s *CISecretSearch) Name() string {
	return s.BaseSource.Name()
}

// Accepts 接受的输入类型
func (s *CISecretSearch) Accepts() []string {
	return []string{"domain", "company"}
}

// NeedsKey 是否需要 API Key
func (s *CISecretSearch) NeedsKey() bool {
	return false
}

// SetConfig 设置配置
func (s *CISecretSearch) SetConfig(cfg map[string]any) error {
	_ = s.BaseSource.SetConfig(cfg)
	s.buildClient()
	return nil
}

// buildClient 构建 HTTP 客户端
func (s *CISecretSearch) buildClient() {
	c := req.C()
	c.SetTimeout(30 * time.Second)
	c.SetUserAgent("Mozilla/5.0 (compatible; Ghost/1.0)")
	s.client = c
}

// Search 执行搜索
func (s *CISecretSearch) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	cfg := &source.SearchConfig{
		MaxAssets: 80,
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
					WithTags("ci", "secret", res.platform).
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
func (s *CISecretSearch) buildDorks(target string) []string {
	platforms := map[string][]string{
		"github_actions":      {"github.com", "site:github.com", "inurl:.github/workflows"},
		"gitlab_ci":           {"gitlab.com", "site:gitlab.com", "inurl:.gitlab-ci.yml"},
		"travis":              {"travis-ci.org", "site:travis-ci.org", "inurl:.travis.yml"},
		"circleci":            {"circleci.com", "site:circleci.com", "inurl:.circleci"},
		"jenkins":             {"github.com", "inurl:Jenkinsfile"},
		"azure_pipelines":     {"github.com", "inurl:azure-pipelines.yml"},
		"bitbucket_pipelines": {"bitbucket.org", "inurl:bitbucket-pipelines.yml"},
		"drone":               {"github.com", "inurl:.drone.yml"},
		"github_pages":        {"github.com", "inurl:_config.yml"},
		"dockerfile":          {"github.com", "inurl:Dockerfile"},
		"kubernetes":          {"github.com", "inurl:deployment.yaml"},
		"terraform":           {"github.com", "inurl:main.tf"},
		"ansible":             {"github.com", "inurl:playbook.yml"},
		"helm":                {"github.com", "inurl:values.yaml"},
	}
	var dorks []string
	for _, parts := range platforms {
		for _, part := range parts {
			dorks = append(dorks, fmt.Sprintf("%s \"%s\"", part, target))
		}
	}
	return dorks
}

// duckduckgo 使用 DuckDuckGo 即时答案 API（无需 key）
func (s *CISecretSearch) duckduckgo(ctx context.Context, query string, limit int) ([]dorkResult, error) {
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
func (s *CISecretSearch) detectPlatform(u string) string {
	u = strings.ToLower(u)
	if strings.Contains(u, "github.com") {
		return "github"
	}
	if strings.Contains(u, "gitlab.com") {
		return "gitlab"
	}
	if strings.Contains(u, "travis-ci.org") {
		return "travis"
	}
	if strings.Contains(u, "circleci.com") {
		return "circleci"
	}
	if strings.Contains(u, "bitbucket.org") {
		return "bitbucket"
	}
	return "unknown"
}
