//go:build broken_recovery
// +build broken_recovery

package github_code

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

// GitHubCode 实现 GitHub 代码搜索
type GitHubCode struct {
	*source.BaseSource
	client *req.Client
}

// NewGitHubCode 创建 GitHubCode
func NewGitHubCode() *GitHubCode {
	s := &GitHubCode{
		BaseSource: source.NewBaseSource("github_code"),
	}
	s.buildClient()
	return s
}

// Name 返回名称
func (s *GitHubCode) Name() string {
	return s.BaseSource.Name()
}

// Accepts 接受的输入类型
func (s *GitHubCode) Accepts() []string {
	return []string{"domain", "company", "keyword"}
}

// NeedsKey 是否需要 API Key
func (s *GitHubCode) NeedsKey() bool {
	return true
}

// SetKey 设置 API Key
func (s *GitHubCode) SetKey(key string) {
	s.BaseSource.SetKey(key)
	s.buildClient()
}

// SetConfig 设置配置
func (s *GitHubCode) SetConfig(cfg map[string]any) error {
	_ = s.BaseSource.SetConfig(cfg)
	s.buildClient()
	return nil
}

// buildClient 构建 HTTP 客户端
func (s *GitHubCode) buildClient() {
	c := req.C()
	c.SetTimeout(30 * time.Second)
	c.SetUserAgent("Mozilla/5.0 (compatible; Ghost/1.0)")
	if s.BaseSource.Key() != "" {
		c.SetCommonHeader("Authorization", "token "+s.BaseSource.Key())
	}
	s.client = c
}

// Search 执行搜索
func (s *GitHubCode) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	if s.client == nil {
		s.buildClient()
	}
	cfg := &source.SearchConfig{
		MaxAssets: 50,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	// 多 dork 遍历，每个 dork 各取一页
	queries := s.buildQueries(target)
	var allAssets []*models.Asset
	seen := make(map[string]struct{})
	for _, query := range queries {
		select {
		case <-ctx.Done():
			return allAssets, ctx.Err()
		default:
		}
		u := fmt.Sprintf("https://api.github.com/search/code?q=%s&per_page=100", url.QueryEscape(query))
		resp, err := s.client.R().SetContext(ctx).Get(u)
		if err != nil {
			return allAssets, fmt.Errorf("request github: %w", err)
		}
		if resp.StatusCode == 403 || resp.StatusCode == 422 {
			break
		}
		if resp.StatusCode != 200 {
			continue
		}
		body := resp.String()
		if !gjson.Valid(body) {
			continue
		}
		for _, item := range gjson.Parse(body).Get("items").Array() {
			htmlURL := item.Get("html_url").String()
			if htmlURL == "" {
				continue
			}
			if _, ok := seen[htmlURL]; ok {
				continue
			}
			seen[htmlURL] = struct{}{}
			repo := item.Get("repository.full_name").String()
			path := item.Get("path").String()
			sha := item.Get("sha").String()
			asset := models.NewAsset().
				WithTitle(fmt.Sprintf("[GitHub] %s/%s", repo, path)).
				WithURL(htmlURL).
				WithSource(s.Name()).
				WithTags("code", "github", "q:"+query).
				WithRaw("repo", repo).WithRaw("path", path).WithRaw("sha", sha)
			allAssets = append(allAssets, asset)
			if len(allAssets) >= cfg.MaxAssets {
				return allAssets, nil
			}
		}
		time.Sleep(2 * time.Second)
	}
	return allAssets, nil
}

// buildQueries 构造多组 dork
func (s *GitHubCode) buildQueries(target string) []string {
	return []string{
		target,
		fmt.Sprintf("%s in:file extension:yaml", target),
		fmt.Sprintf("%s in:file extension:yml", target),
		fmt.Sprintf("%s in:file extension:env", target),
		fmt.Sprintf("%s in:file extension:conf", target),
		fmt.Sprintf("%s in:file extension:ini", target),
		fmt.Sprintf("%s in:file extension:properties", target),
	}
}
