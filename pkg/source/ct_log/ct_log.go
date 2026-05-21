package ct_log

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

// CTLog 证书透明度日志查询（crt.sh）
type CTLog struct {
	*source.BaseSource
	client *req.Client
}

func NewCTLog() *CTLog {
	s := &CTLog{BaseSource: source.NewBaseSource("ct_log")}
	s.client = req.C().SetTimeout(30 * time.Second).SetUserAgent("Ghost/1.0")
	return s
}

func (s *CTLog) Name() string                       { return s.BaseSource.Name() }
func (s *CTLog) Accepts() []string                  { return []string{"domain"} }
func (s *CTLog) NeedsKey() bool                     { return false }
func (s *CTLog) SetConfig(cfg map[string]any) error { return s.BaseSource.SetConfig(cfg) }

func (s *CTLog) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	cfg := &source.SearchConfig{MaxAssets: 500}
	for _, opt := range opts {
		opt(cfg)
	}
	// crt.sh 的 ?q=%.<domain> 形式偶发 404/502，依次尝试多种查询并对
	// 非 JSON 响应静默返回空（站点压力大时会回退到 HTML 错误页）。
	urls := []string{
		fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", url.QueryEscape(target)),
		fmt.Sprintf("https://crt.sh/?q=%s&output=json", url.QueryEscape(target)),
	}
	var body string
	var lastStatus int
	var lastErr error
	for _, u := range urls {
		resp, err := s.client.R().SetContext(ctx).Get(u)
		if err != nil {
			lastErr = err
			continue
		}
		lastStatus = resp.StatusCode
		if resp.StatusCode == 200 && gjson.Valid(resp.String()) {
			body = resp.String()
			break
		}
	}
	if body == "" {
		if lastErr != nil {
			return nil, fmt.Errorf("ct_log request: %w", lastErr)
		}
		if lastStatus == 404 || lastStatus == 502 || lastStatus == 503 {
			return nil, nil // 站点压力，视为空
		}
		return nil, nil
	}
	var assets []*models.Asset
	seen := make(map[string]bool)
	for _, item := range gjson.Parse(body).Array() {
		name := item.Get("name_value").String()
		issuer := item.Get("issuer_name").String()
		notBefore := item.Get("not_before").String()
		notAfter := item.Get("not_after").String()
		for _, d := range splitLines(name) {
			if d == "" || seen[d] {
				continue
			}
			seen[d] = true
			a := models.NewAsset().WithTitle(fmt.Sprintf("[CT] %s", d)).
				WithHost(d).WithDomain(d).WithSource(s.Name()).
				WithTags("ctlog", "cert").
				WithRaw("issuer", issuer).WithRaw("not_before", notBefore).WithRaw("not_after", notAfter)
			assets = append(assets, a)
			if len(assets) >= cfg.MaxAssets {
				return assets, nil
			}
		}
	}
	return assets, nil
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i, c := range s {
		if c == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	out = append(out, s[start:])
	return out
}
