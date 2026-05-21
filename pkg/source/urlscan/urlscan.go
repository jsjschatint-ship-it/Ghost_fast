package urlscan

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

type URLScan struct {
	*source.BaseSource
	client *req.Client
}

func NewURLScan() *URLScan {
	s := &URLScan{BaseSource: source.NewBaseSource("urlscan")}
	s.client = req.C().SetTimeout(30 * time.Second).SetUserAgent("Ghost/1.0")
	return s
}

func (s *URLScan) Name() string                       { return s.BaseSource.Name() }
func (s *URLScan) Accepts() []string                  { return []string{"domain", "url", "ip"} }
func (s *URLScan) NeedsKey() bool                     { return false }
func (s *URLScan) SetConfig(cfg map[string]any) error { return s.BaseSource.SetConfig(cfg) }

func (s *URLScan) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	cfg := &source.SearchConfig{MaxAssets: 100}
	for _, opt := range opts {
		opt(cfg)
	}
	u := fmt.Sprintf("https://urlscan.io/api/v1/search/?q=domain:%s&size=100", url.QueryEscape(target))
	resp, err := s.client.R().SetContext(ctx).Get(u)
	if err != nil {
		return nil, fmt.Errorf("urlscan: %w", err)
	}
	var assets []*models.Asset
	for _, item := range gjson.Parse(resp.String()).Get("results").Array() {
		urlVal := item.Get("page.url").String()
		ip := item.Get("page.ip").String()
		domain := item.Get("page.domain").String()
		title := item.Get("page.title").String()
		a := models.NewAsset().WithTitle(fmt.Sprintf("[URLScan] %s", title)).
			WithURL(urlVal).WithIP(ip).WithDomain(domain).WithHost(domain).
			WithSource(s.Name()).WithTags("urlscan", "scan").
			WithRaw("title", title).WithRaw("country", item.Get("page.country").String())
		assets = append(assets, a)
		if len(assets) >= cfg.MaxAssets {
			break
		}
	}
	return assets, nil
}
