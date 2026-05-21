package ipinfo

import (
	"context"
	"fmt"
	"time"

	"github.com/imroc/req/v3"
	"github.com/tidwall/gjson"
	"github.com/wgpsec/ENScan/pkg/models"
	"github.com/wgpsec/ENScan/pkg/source"
)

type IPInfo struct {
	*source.BaseSource
	client *req.Client
}

func NewIPInfo() *IPInfo {
	s := &IPInfo{BaseSource: source.NewBaseSource("ipinfo")}
	s.client = req.C().SetTimeout(30 * time.Second).SetUserAgent("Ghost/1.0")
	return s
}

func (s *IPInfo) Name() string                       { return s.BaseSource.Name() }
func (s *IPInfo) Accepts() []string                  { return []string{"ip"} }
func (s *IPInfo) NeedsKey() bool                     { return false }
func (s *IPInfo) SetKey(k string)                    { s.BaseSource.SetKey(k) }
func (s *IPInfo) SetConfig(cfg map[string]any) error { return s.BaseSource.SetConfig(cfg) }

func (s *IPInfo) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	u := fmt.Sprintf("https://ipinfo.io/%s/json?token=%s", target, s.BaseSource.Key())
	resp, err := s.client.R().SetContext(ctx).Get(u)
	if err != nil {
		return nil, fmt.Errorf("ipinfo: %w", err)
	}
	d := gjson.Parse(resp.String())
	a := models.NewAsset().WithTitle(fmt.Sprintf("[IPInfo] %s", target)).WithIP(target).
		WithSource(s.Name()).WithTags("ipinfo", "geo").
		WithRaw("country", d.Get("country").String()).
		WithRaw("city", d.Get("city").String()).
		WithRaw("region", d.Get("region").String()).
		WithRaw("org", d.Get("org").String()).
		WithRaw("postal", d.Get("postal").String())
	return []*models.Asset{a}, nil
}
