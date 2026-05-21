// Package github_org GitHub 组织枚举（公开数据）。
// 通过域名/公司名找 GitHub Org，列仓库 + 公开成员。
// 完全使用 GitHub 公开 API，不接触目标。
package github_org

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/imroc/req/v3"
	"github.com/tidwall/gjson"
	"github.com/wgpsec/ENScan/pkg/models"
	"github.com/wgpsec/ENScan/pkg/source"
)

const ghAPI = "https://api.github.com"

var reScheme = regexp.MustCompile(`^https?://`)

// GitHubOrg 数据源
type GitHubOrg struct {
	*source.BaseSource
	client     *req.Client
	maxRepos   int
	maxMembers int
}

// New 创建
func New() *GitHubOrg {
	return &GitHubOrg{
		BaseSource: source.NewBaseSource("github_org"),
		client:     req.C().SetTimeout(30 * time.Second).SetUserAgent("PassiveRecon/1.0"),
		maxRepos:   100,
		maxMembers: 50,
	}
}

// Accepts 接受的输入类型
func (g *GitHubOrg) Accepts() []string { return []string{"domain", "company", "keyword"} }

// NeedsKey 是否需要 API Key
func (g *GitHubOrg) NeedsKey() bool { return false }

// SetConfig 配置
func (g *GitHubOrg) SetConfig(cfg map[string]any) error {
	_ = g.BaseSource.SetConfig(cfg)
	if v, ok := cfg["proxy"].(string); ok && v != "" {
		g.client.SetProxyURL(v)
	}
	if v, ok := cfg["timeout"].(int); ok && v > 0 {
		g.client.SetTimeout(time.Duration(v) * time.Second)
	}
	if v, ok := cfg["max_repos"].(int); ok && v > 0 {
		g.maxRepos = v
	}
	if v, ok := cfg["max_members"].(int); ok && v > 0 {
		g.maxMembers = v
	}
	if v, ok := cfg["token"].(string); ok && v != "" {
		g.SetKey(v)
	}
	return nil
}

// candidates 根据域名/公司名生成可能的 Org 名
func candidates(target string) []string {
	t := strings.ToLower(strings.TrimSpace(target))
	if t == "" {
		return nil
	}
	if strings.HasPrefix(t, "http") {
		t = reScheme.ReplaceAllString(t, "")
		t = strings.SplitN(t, "/", 2)[0]
	}
	cs := []string{t}
	if strings.Contains(t, ".") {
		prefix := strings.SplitN(t, ".", 2)[0]
		cs = append(cs, prefix, prefix+"tech", prefix+"lab", prefix+"labs", prefix+"inc", prefix+"-org")
		if p2 := strings.ReplaceAll(prefix, "-", ""); p2 != prefix {
			cs = append(cs, p2)
		}
	}
	seen := map[string]bool{}
	out := []string{}
	for _, c := range cs {
		if c != "" && !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	return out
}

func (g *GitHubOrg) headers() map[string]string {
	h := map[string]string{
		"Accept":               "application/vnd.github+json",
		"X-GitHub-Api-Version": "2022-11-28",
	}
	if tok := g.Key(); tok != "" {
		h["Authorization"] = "Bearer " + tok
	}
	return h
}

// Search 执行搜索
func (g *GitHubOrg) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	cfg := &source.SearchConfig{}
	for _, opt := range opts {
		opt(cfg)
	}
	if target == "" {
		return nil, nil
	}
	headers := g.headers()

	// 1) 找到匹配的 org
	var orgInfo gjson.Result
	var orgLogin string
	for _, cand := range candidates(target) {
		resp, err := g.client.R().SetContext(ctx).SetHeaders(headers).
			Get(fmt.Sprintf("%s/orgs/%s", ghAPI, url.PathEscape(cand)))
		if err != nil {
			continue
		}
		if resp.StatusCode == 200 {
			orgInfo = gjson.Parse(resp.String())
			orgLogin = cand
			break
		}
		if resp.StatusCode == 403 || resp.StatusCode == 429 {
			break // 速率限制
		}
	}
	if orgLogin == "" {
		return nil, nil
	}

	out := []*models.Asset{}
	blog := strings.TrimSpace(orgInfo.Get("blog").String())
	blogHost := ""
	if blog != "" {
		blogHost = strings.SplitN(reScheme.ReplaceAllString(blog, ""), "/", 2)[0]
	}
	desc := orgInfo.Get("description").String()
	if len(desc) > 120 {
		desc = desc[:120]
	}
	orgAsset := models.NewAsset().
		WithDomain(blogHost).WithHost(blogHost).
		WithURL(orgInfo.Get("html_url").String()).
		WithTitle(desc).
		WithOrg(stringOr(orgInfo.Get("name").String(), orgLogin)).
		WithUpdateTime(orgInfo.Get("updated_at").String()).
		WithSource("github_org").
		WithTags("GitHub-Org")
	orgAsset.Normalize()
	out = append(out, orgAsset)

	// 2) 仓库
	repoResp, err := g.client.R().SetContext(ctx).SetHeaders(headers).
		SetQueryParam("per_page", fmt.Sprintf("%d", min(100, g.maxRepos))).
		SetQueryParam("sort", "updated").
		SetQueryParam("type", "public").
		Get(fmt.Sprintf("%s/orgs/%s/repos", ghAPI, url.PathEscape(orgLogin)))
	if err == nil && repoResp.StatusCode == 200 {
		for i, r := range gjson.Parse(repoResp.String()).Array() {
			if i >= g.maxRepos {
				break
			}
			home := strings.TrimSpace(r.Get("homepage").String())
			homeHost := ""
			if home != "" {
				homeHost = strings.SplitN(reScheme.ReplaceAllString(home, ""), "/", 2)[0]
			}
			tags := []string{"GitHub-Repo"}
			if r.Get("fork").Bool() {
				tags = append(tags, "fork")
			}
			if r.Get("archived").Bool() {
				tags = append(tags, "archived")
			}
			rdesc := r.Get("description").String()
			if len(rdesc) > 120 {
				rdesc = rdesc[:120]
			}
			a := models.NewAsset().
				WithDomain(homeHost).WithHost(homeHost).
				WithURL(r.Get("html_url").String()).
				WithTitle(rdesc).
				WithOrg(orgLogin).
				WithUpdateTime(r.Get("updated_at").String()).
				WithSource("github_org").
				WithTags(tags...)
			a.WithRaw("name", r.Get("full_name").String())
			a.WithRaw("language", r.Get("language").String())
			a.Normalize()
			out = append(out, a)
		}
	}

	// 3) 公开成员
	memResp, err := g.client.R().SetContext(ctx).SetHeaders(headers).
		SetQueryParam("per_page", fmt.Sprintf("%d", min(100, g.maxMembers))).
		Get(fmt.Sprintf("%s/orgs/%s/public_members", ghAPI, url.PathEscape(orgLogin)))
	if err == nil && memResp.StatusCode == 200 {
		for i, m := range gjson.Parse(memResp.String()).Array() {
			if i >= g.maxMembers {
				break
			}
			a := models.NewAsset().
				WithURL(m.Get("html_url").String()).
				WithTitle("@" + m.Get("login").String()).
				WithOrg(orgLogin).
				WithSource("github_org").
				WithTags("GitHub-Member")
			a.Normalize()
			out = append(out, a)
		}
	}
	return out, nil
}

func stringOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
