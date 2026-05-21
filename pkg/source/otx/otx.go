package otx

import (
	"context"
	"fmt"
	"time"

	"github.com/imroc/req/v3"
	"github.com/tidwall/gjson"
	"github.com/wgpsec/ENScan/pkg/models"
	"github.com/wgpsec/ENScan/pkg/source"
)

type OTX struct {
	*source.BaseSource
	client *req.Client
}

func NewOTX() *OTX {
	s := &OTX{BaseSource: source.NewBaseSource("otx")}
	s.client = req.C().SetTimeout(30 * time.Second).SetUserAgent("Ghost/1.0")
	return s
}

func (s *OTX) Name() string                       { return s.BaseSource.Name() }
func (s *OTX) Accepts() []string                  { return []string{"domain", "ip"} }
func (s *OTX) NeedsKey() bool                     { return false }
func (s *OTX) SetConfig(cfg map[string]any) error { return s.BaseSource.SetConfig(cfg) }

func (s *OTX) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	cfg := &source.SearchConfig{MaxAssets: 500}
	for _, opt := range opts {
		opt(cfg)
	}
	u := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns", target)
	resp, err := s.client.R().SetContext(ctx).Get(u)
	if err != nil {
		return nil, fmt.Errorf("otx: %w", err)
	}
	var assets []*models.Asset
	for _, item := range gjson.Parse(resp.String()).Get("passive_dns").Array() {
		host := item.Get("hostname").String()
		ip := item.Get("address").String()
		a := models.NewAsset().WithTitle(fmt.Sprintf("[OTX] %s", host)).
			WithHost(host).WithDomain(host).WithIP(ip).WithSource(s.Name()).
			WithTags("otx", "pdns").WithRaw("first", item.Get("first").String()).
			WithRaw("last", item.Get("last").String())
		assets = append(assets, a)
		if len(assets) >= cfg.MaxAssets {
			break
		}
	}
	return assets, nil
}
