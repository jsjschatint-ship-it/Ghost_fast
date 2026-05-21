package netlas

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

type Netlas struct {
	*source.BaseSource
	client *req.Client
}

func NewNetlas() *Netlas {
	s := &Netlas{BaseSource: source.NewBaseSource("netlas")}
	s.client = req.C().SetTimeout(30 * time.Second).SetUserAgent("Ghost/1.0")
	return s
}

func (s *Netlas) Name() string                       { return s.BaseSource.Name() }
func (s *Netlas) Accepts() []string                  { return []string{"domain", "ip"} }
func (s *Netlas) NeedsKey() bool                     { return true }
func (s *Netlas) SetKey(k string)                    { s.BaseSource.SetKey(k) }
func (s *Netlas) SetConfig(cfg map[string]any) error { return s.BaseSource.SetConfig(cfg) }

func (s *Netlas) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	cfg := &source.SearchConfig{MaxAssets: 200}
	for _, opt := range opts {
		opt(cfg)
	}
	query := fmt.Sprintf(`domain:%s`, target)
	u := fmt.Sprintf("https://app.netlas.io/api/responses/?q=%s&size=%d", url.QueryEscape(query), cfg.MaxAssets)
	resp, err := s.client.R().SetContext(ctx).SetHeader("X-API-Key", s.BaseSource.Key()).Get(u)
	if err != nil {
		return nil, fmt.Errorf("netlas: %w", err)
	}
	var assets []*models.Asset
	for _, item := range gjson.Parse(resp.String()).Get("items").Array() {
		ip := item.Get("data.ip").String()
		port := item.Get("data.port").Int()
		host := item.Get("data.host").String()
		title := item.Get("data.http.title").String()
		a := models.NewAsset().WithTitle(fmt.Sprintf("[Netlas] %s:%d", ip, port)).
			WithIP(ip).WithPort(int(port)).WithHost(host).WithTitle(title).
			WithSource(s.Name()).WithTags("netlas", "asset")
		assets = append(assets, a)
		if len(assets) >= cfg.MaxAssets {
			break
		}
	}
	return assets, nil
}
