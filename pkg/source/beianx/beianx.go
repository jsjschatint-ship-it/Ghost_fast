// Package beianx beianx.cn 备案号/公司名反查全部备案域名（国内最强 ICP 横向枢纽）。
//
// Python 版用 Playwright 跑 JS 挑战，Go 版采用纯 HTTP + cookie 注入路径：
//   - 默认 enabled=false（避免不带 cookie 触发"请求过于频繁"）
//   - 用户可在 config 提供 cookie（浏览器登录后 F12 复制）以绕过限频
//   - 检测到 JS 挑战 / rate-limit 时返回可读错误，而非空结果
package beianx

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/imroc/req/v3"
	"github.com/wgpsec/ENScan/pkg/models"
	"github.com/wgpsec/ENScan/pkg/source"
)

const (
	homepage           = "https://www.beianx.cn"
	searchURLTpl       = homepage + "/search/%s"
	defaultUA          = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
	challengeTitleMark = "查询中"
)

var rateLimitMarks = []string{"请求过于频繁", "请稍后再试", "返回并登录"}

// Beianx 数据源
type Beianx struct {
	*source.BaseSource
	client  *req.Client
	enabled bool
	cookie  string
}

// NewBeianx 创建
func NewBeianx() *Beianx {
	return &Beianx{
		BaseSource: source.NewBaseSource("beianx"),
		client:     req.C().SetTimeout(30 * time.Second).SetUserAgent(defaultUA),
	}
}

// Accepts 接受的输入类型
func (s *Beianx) Accepts() []string { return []string{"company", "domain", "icp"} }

// NeedsKey 是否需要 API Key
func (s *Beianx) NeedsKey() bool { return false }

// SetConfig 配置（enabled / cookie / proxy / timeout）
func (s *Beianx) SetConfig(cfg map[string]any) error {
	_ = s.BaseSource.SetConfig(cfg)
	if v, ok := cfg["enabled"].(bool); ok {
		s.enabled = v
	}
	if v, ok := cfg["cookie"].(string); ok {
		s.cookie = strings.TrimSpace(v)
	}
	if v, ok := cfg["proxy"].(string); ok && v != "" {
		s.client.SetProxyURL(v)
	}
	if v, ok := cfg["timeout"].(int); ok && v > 0 {
		s.client.SetTimeout(time.Duration(v) * time.Second)
	}
	return nil
}

// Search 执行搜索
func (s *Beianx) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return nil, nil
	}
	// 默认关闭：与 Python 版一致，静默返回空（避免污染聚合结果）
	if !s.enabled {
		return nil, nil
	}
	r := s.client.R().
		SetContext(ctx).
		SetHeader("Accept-Language", "zh-CN,zh;q=0.9").
		SetHeader("Referer", homepage+"/")
	if s.cookie != "" {
		r.SetHeader("Cookie", s.cookie)
	}
	u := fmt.Sprintf(searchURLTpl, url.PathEscape(target))
	resp, err := r.Get(u)
	if err != nil {
		return nil, fmt.Errorf("beianx request: %w", err)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("beianx http %d", resp.StatusCode)
	}
	html := resp.String()

	// rate-limit / JS 挑战：返回明确错误而非伪造 asset，
	// 让 smoke / runner 把它正确归类为 auth_required 而不是 ok。
	for _, m := range rateLimitMarks {
		if strings.Contains(html, m) {
			return nil, fmt.Errorf("beianx rate-limit: %s (configure cookie or switch IP)", m)
		}
	}
	if strings.Contains(html, challengeTitleMark) || strings.Contains(html, "jsjiami") {
		return nil, fmt.Errorf("beianx JS challenge unresolved (paste browser cookie via config)")
	}

	return parseTable(html, target)
}

// parseTable 从结果页 HTML 抽出资产行
// 每行 7~8 列：序号 | 公司名 | 性质 | 备案号 | 网站名 | 域名 | 审核日期 | 详情
func parseTable(html, query string) ([]*models.Asset, error) {
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(html))
	if err != nil {
		return nil, fmt.Errorf("beianx parse html: %w", err)
	}

	seen := map[string]bool{}
	var out []*models.Asset
	reICPRoot := regexp.MustCompile(`^(.+?)-\d+$`)

	doc.Find("tr").Each(func(_ int, tr *goquery.Selection) {
		var cells []string
		tr.Find("td,th").Each(func(_ int, c *goquery.Selection) {
			cells = append(cells, strings.TrimSpace(c.Text()))
		})
		if len(cells) < 6 {
			return
		}
		// 抛掉表头
		idx := cells[0]
		if idx == "序号" || idx == "#" {
			return
		}
		if _, err := fmtParseUint(idx); err != nil {
			return
		}
		org := safeIdx(cells, 1)
		nature := safeIdx(cells, 2)
		icp := safeIdx(cells, 3)
		siteName := safeIdx(cells, 4)
		domain := strings.ToLower(safeIdx(cells, 5))
		domain = strings.TrimPrefix(domain, "www.")
		updateTime := safeIdx(cells, 6)
		if domain == "" || !strings.Contains(domain, ".") {
			return
		}
		key := domain + "|" + icp
		if seen[key] {
			return
		}
		seen[key] = true

		tags := []string{"beianx"}
		if nature != "" {
			tags = append(tags, "主体:"+nature)
		}
		if m := reICPRoot.FindStringSubmatch(icp); len(m) > 1 {
			tags = append(tags, "备案号:"+m[1])
		}
		q := query
		if len(q) > 40 {
			q = q[:40]
		}
		tags = append(tags, "查询:"+q)

		a := models.NewAsset().
			WithDomain(domain).
			WithHost(domain).
			WithOrg(org).
			WithICP(icp).
			WithTitle(siteName).
			WithUpdateTime(updateTime).
			WithSource("beianx").
			WithTags(tags...)
		for i, c := range cells {
			a.WithRaw(fmt.Sprintf("col%d", i), c)
		}
		a.Normalize()
		out = append(out, a)
	})
	return out, nil
}

func safeIdx(s []string, i int) string {
	if i < len(s) {
		return s[i]
	}
	return ""
}

func fmtParseUint(s string) (uint64, error) {
	var n uint64
	if s == "" {
		return 0, fmt.Errorf("empty")
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("nan")
		}
		n = n*10 + uint64(c-'0')
	}
	return n, nil
}
