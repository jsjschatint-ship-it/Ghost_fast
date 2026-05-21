package hibp

// HaveIBeenPwned (HIBP) - 真实泄露库。需付费 key（约 $3.50/月）。
// 对收集到的 email 资产逐个查 /api/v3/breachedaccount/<email>?truncateResponse=false
// 限速：1.5s/req（这里取 1.6s 保险）。
// 没有 email 输入则什么都不做。

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/imroc/req/v3"
	"github.com/tidwall/gjson"
	"github.com/wgpsec/ENScan/pkg/models"
	"github.com/wgpsec/ENScan/pkg/source"
)

const hibpBase = "https://haveibeenpwned.com/api/v3"

type HIBP struct {
	*source.BaseSource
	client *req.Client
}

func NewHIBP() *HIBP {
	return &HIBP{
		BaseSource: source.NewBaseSource("hibp"),
		client:     req.C().SetTimeout(30 * time.Second).SetUserAgent("PassiveRecon/1.0"),
	}
}

func (s *HIBP) Name() string      { return s.BaseSource.Name() }
func (s *HIBP) Accepts() []string { return []string{"email"} }
func (s *HIBP) NeedsKey() bool    { return true }

// collectEmails 从 SetConfig({"existing_assets": [...]}) 或 target=email 抽 email
func (s *HIBP) collectEmails(target string) []string {
	emails := []string{}
	seen := map[string]struct{}{}
	add := func(e string) {
		e = strings.ToLower(strings.TrimSpace(e))
		if e == "" || !strings.Contains(e, "@") {
			return
		}
		if _, ok := seen[e]; ok {
			return
		}
		seen[e] = struct{}{}
		emails = append(emails, e)
	}
	if strings.Contains(target, "@") {
		add(target)
	}
	c := s.BaseSource.Config()
	if c == nil {
		return emails
	}
	if existing, ok := c["existing_assets"].([]*models.Asset); ok {
		for _, a := range existing {
			if a != nil && a.Service == "email" {
				add(a.Title)
			}
		}
	}
	// 兼容 []any（YAML/JSON 解码后常态）
	if existing, ok := c["existing_assets"].([]any); ok {
		for _, raw := range existing {
			if m, ok2 := raw.(map[string]any); ok2 {
				if svc, _ := m["service"].(string); svc == "email" {
					if title, _ := m["title"].(string); title != "" {
						add(title)
					}
				}
			}
		}
	}
	return emails
}

func (s *HIBP) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	cfg := &source.SearchConfig{MaxAssets: 500}
	for _, opt := range opts {
		opt(cfg)
	}
	key := s.BaseSource.Key()
	if key == "" {
		return nil, fmt.Errorf("hibp needs api key")
	}
	emails := s.collectEmails(target)
	if len(emails) == 0 {
		return nil, nil
	}
	if len(emails) > 100 {
		emails = emails[:100] // HIBP 限速保护
	}

	out := make([]*models.Asset, 0, len(emails))
	for i, email := range emails {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		u := fmt.Sprintf("%s/breachedaccount/%s?truncateResponse=false",
			hibpBase, url.PathEscape(email))
		resp, err := s.client.R().
			SetContext(ctx).
			SetHeader("hibp-api-key", key).
			Get(u)
		if i+1 < len(emails) {
			time.Sleep(1600 * time.Millisecond) // HIBP rate limit
		}
		if err != nil {
			continue
		}
		if resp.StatusCode == 404 {
			continue
		}
		if resp.StatusCode != 200 {
			// 401/429 等：返回一条错误 asset 提示，但不中断
			if resp.StatusCode == 401 || resp.StatusCode == 403 {
				return out, fmt.Errorf("hibp http %d (key bad)", resp.StatusCode)
			}
			continue
		}
		body := resp.String()
		if !gjson.Valid(body) {
			continue
		}
		breaches := gjson.Parse(body).Array()
		if len(breaches) == 0 {
			continue
		}
		names := make([]string, 0, len(breaches))
		worstDate := ""
		for _, b := range breaches {
			if n := b.Get("Name").String(); n != "" {
				names = append(names, n)
			}
			if d := b.Get("BreachDate").String(); d > worstDate {
				worstDate = d
			}
		}
		host := ""
		if at := strings.Index(email, "@"); at >= 0 {
			host = email[at+1:]
		}
		a := models.NewAsset().
			WithDomain(host).
			WithHost(host).
			WithTitle(email).
			WithService("email").
			WithSource(s.Name()).
			WithTags("pwned", fmt.Sprintf("breach-count:%d", len(breaches)))
		// 最多 5 个 breach 名作 tag
		topN := len(names)
		if topN > 5 {
			topN = 5
		}
		for i := 0; i < topN; i++ {
			a = a.WithTags("breach:" + names[i])
		}
		if worstDate != "" {
			a = a.WithTags("latest:" + worstDate)
		}
		out = append(out, a)
		if cfg.MaxAssets > 0 && len(out) >= cfg.MaxAssets {
			break
		}
	}
	return out, nil
}
