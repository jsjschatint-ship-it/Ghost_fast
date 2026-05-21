package internetdb

import (
	"context"
	"fmt"
	"time"

	"github.com/imroc/req/v3"
	"github.com/tidwall/gjson"
	"github.com/wgpsec/ENScan/pkg/models"
	"github.com/wgpsec/ENScan/pkg/source"
)

// InternetDB Shodan 免费 IP 信息 API
type InternetDB struct {
	*source.BaseSource
	client *req.Client
}

func NewInternetDB() *InternetDB {
	s := &InternetDB{BaseSource: source.NewBaseSource("internetdb")}
	s.client = req.C().SetTimeout(30 * time.Second).SetUserAgent("Ghost/1.0")
	return s
}

func (s *InternetDB) Name() string                       { return s.BaseSource.Name() }
func (s *InternetDB) Accepts() []string                  { return []string{"ip"} }
func (s *InternetDB) NeedsKey() bool                     { return false }
func (s *InternetDB) SetConfig(cfg map[string]any) error { return s.BaseSource.SetConfig(cfg) }

func (s *InternetDB) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	u := fmt.Sprintf("https://internetdb.shodan.io/%s", target)
	resp, err := s.client.R().SetContext(ctx).Get(u)
	if err != nil {
		return nil, fmt.Errorf("internetdb: %w", err)
	}
	if resp.StatusCode != 200 {
		return nil, nil
	}
	d := gjson.Parse(resp.String())
	var assets []*models.Asset
	for _, p := range d.Get("ports").Array() {
		port := int(p.Int())
		a := models.NewAsset().WithTitle(fmt.Sprintf("[InternetDB] %s:%d", target, port)).
			WithIP(target).WithPort(port).WithSource(s.Name()).WithTags("internetdb", "shodan").
			WithRaw("hostnames", d.Get("hostnames").String()).
			WithRaw("vulns", d.Get("vulns").String()).
			WithRaw("cpes", d.Get("cpes").String())
		assets = append(assets, a)
	}
	return assets, nil
}
