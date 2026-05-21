package certspotter

import (
	"context"
	"fmt"
	"time"

	"github.com/imroc/req/v3"
	"github.com/tidwall/gjson"
	"github.com/wgpsec/ENScan/pkg/models"
	"github.com/wgpsec/ENScan/pkg/source"
)

type CertSpotter struct {
	*source.BaseSource
	client *req.Client
}

func NewCertSpotter() *CertSpotter {
	s := &CertSpotter{BaseSource: source.NewBaseSource("certspotter")}
	s.client = req.C().SetTimeout(30 * time.Second).SetUserAgent("Ghost/1.0")
	return s
}

func (s *CertSpotter) Name() string                       { return s.BaseSource.Name() }
func (s *CertSpotter) Accepts() []string                  { return []string{"domain"} }
func (s *CertSpotter) NeedsKey() bool                     { return false }
func (s *CertSpotter) SetConfig(cfg map[string]any) error { return s.BaseSource.SetConfig(cfg) }

func (s *CertSpotter) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	cfg := &source.SearchConfig{MaxAssets: 500}
	for _, opt := range opts {
		opt(cfg)
	}
	u := fmt.Sprintf("https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names", target)
	resp, err := s.client.R().SetContext(ctx).Get(u)
	if err != nil {
		return nil, fmt.Errorf("certspotter: %w", err)
	}
	seen := make(map[string]bool)
	var assets []*models.Asset
	for _, item := range gjson.Parse(resp.String()).Array() {
		for _, name := range item.Get("dns_names").Array() {
			host := name.String()
			if seen[host] {
				continue
			}
			seen[host] = true
			a := models.NewAsset().WithTitle(fmt.Sprintf("[CertSpotter] %s", host)).
				WithHost(host).WithDomain(host).WithSource(s.Name()).WithTags("ctlog", "certspotter")
			assets = append(assets, a)
			if len(assets) >= cfg.MaxAssets {
				return assets, nil
			}
		}
	}
	return assets, nil
}
