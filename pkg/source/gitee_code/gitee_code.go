package gitee_code

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/imroc/req/v3"
	"github.com/wgpsec/ENScan/pkg/models"
	"github.com/wgpsec/ENScan/pkg/source"
)

var reGiteeRepo = regexp.MustCompile(`href="(/[^"]+/[^"]+/blob/[^"]+)"`)

var giteeDefaultDorks = []string{
	`"%s" password`,
	`"%s" api_key`,
	`"%s" secret`,
	`"%s" token`,
	`"%s" LTAI`,
	`"%s" aliyun_access_key`,
	`"%s" oss.aliyuncs.com`,
	`"%s" AKID`,
	`"%s" SecretKey`,
	`"%s" myqcloud.com`,
	`"%s" myhuaweicloud.com`,
	`"%s" AKLT`,
	`"%s" AKIA`,
	`"%s" AIza`,
	`"%s" application.properties`,
	`"%s" application.yml`,
	`"%s" jdbc:mysql`,
	`"%s" "BEGIN RSA PRIVATE KEY"`,
}

// GiteeCode 实现 Gitee 代码搜索
type GiteeCode struct {
	*source.BaseSource
	client *req.Client
}

// NewGiteeCode 创建 GiteeCode
func NewGiteeCode() *GiteeCode {
	g := &GiteeCode{
		BaseSource: source.NewBaseSource("gitee_code"),
	}
	g.buildClient()
	return g
}

// Name 返回名称
func (g *GiteeCode) Name() string {
	return g.BaseSource.Name()
}

// Accepts 接受的输入类型
func (g *GiteeCode) Accepts() []string {
	return []string{"domain", "company", "keyword"}
}

// NeedsKey 是否需要 API Key
func (g *GiteeCode) NeedsKey() bool {
	return false
}

// SetConfig 设置配置
func (g *GiteeCode) SetConfig(cfg map[string]any) error {
	_ = g.BaseSource.SetConfig(cfg)
	g.buildClient()
	return nil
}

// buildClient 构建 HTTP 客户端
func (g *GiteeCode) buildClient() {
	c := req.C()
	c.SetTimeout(30 * time.Second)
	c.SetUserAgent("Mozilla/5.0 (compatible; Ghost/1.0)")
	g.client = c
}

// Search 执行搜索
func (g *GiteeCode) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	cfg := &source.SearchConfig{MaxAssets: 50}
	for _, opt := range opts {
		opt(cfg)
	}
	target = strings.ToLower(strings.TrimSpace(target))
	if target == "" || !strings.Contains(target, ".") {
		return nil, nil
	}
	var out []*models.Asset
	seen := make(map[string]struct{})
	for _, tpl := range giteeDefaultDorks {
		select {
		case <-ctx.Done():
			return out, ctx.Err()
		default:
		}
		q := fmt.Sprintf(tpl, target)
		u := fmt.Sprintf("https://search.gitee.com/?type=code&q=%s", url.QueryEscape(q))
		resp, err := g.client.R().SetContext(ctx).Get(u)
		if err != nil || resp.StatusCode != 200 {
			continue
		}
		for _, m := range reGiteeRepo.FindAllStringSubmatch(resp.String(), -1) {
			path := m[1]
			full := "https://gitee.com" + path
			if _, ok := seen[full]; ok {
				continue
			}
			seen[full] = struct{}{}
			title := path
			if len(title) > 200 {
				title = title[:200]
			}
			tagDork := tpl
			if idx := strings.Index(tpl, `" `); idx >= 0 {
				tagDork = strings.TrimSpace(tpl[idx+2:])
				if len(tagDork) > 30 {
					tagDork = tagDork[:30]
				}
			}
			a := models.NewAsset().
				WithURL(full).WithHost(target).WithDomain(target).
				WithTitle(title).
				WithSource(g.Name()).
				WithTags("gitee", "code", "q:"+tagDork)
			out = append(out, a)
			if len(out) >= cfg.MaxAssets {
				return out, nil
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	return out, nil
}
