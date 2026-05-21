package bgp_he

import (
	"context"
	"fmt"
	"regexp"
	"time"

	"github.com/imroc/req/v3"
	"github.com/wgpsec/ENScan/pkg/models"
	"github.com/wgpsec/ENScan/pkg/source"
)

// BGPHE 通过 Hurricane Electric (bgp.he.net) 查询 ASN/IP 段
type BGPHE struct {
	*source.BaseSource
	client *req.Client
}

func NewBGPHE() *BGPHE {
	s := &BGPHE{BaseSource: source.NewBaseSource("bgp_he")}
	s.client = req.C().SetTimeout(30 * time.Second).SetUserAgent("Mozilla/5.0")
	return s
}

func (s *BGPHE) Name() string                       { return s.BaseSource.Name() }
func (s *BGPHE) Accepts() []string                  { return []string{"asn", "ip", "company"} }
func (s *BGPHE) NeedsKey() bool                     { return false }
func (s *BGPHE) SetConfig(cfg map[string]any) error { return s.BaseSource.SetConfig(cfg) }

func (s *BGPHE) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	cfg := &source.SearchConfig{MaxAssets: 500}
	for _, opt := range opts {
		opt(cfg)
	}
	u := fmt.Sprintf("https://bgp.he.net/search?search%%5Bsearch%%5D=%s&commit=Search", target)
	resp, err := s.client.R().SetContext(ctx).Get(u)
	if err != nil {
		return nil, fmt.Errorf("bgp.he.net: %w", err)
	}
	asnRE := regexp.MustCompile(`AS(\d+)`)
	cidrRE := regexp.MustCompile(`\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})\b`)
	var assets []*models.Asset
	for _, m := range asnRE.FindAllStringSubmatch(resp.String(), -1) {
		asn := "AS" + m[1]
		a := models.NewAsset().WithTitle(fmt.Sprintf("[BGP.HE] %s", asn)).
			WithASN(asn).WithSource(s.Name()).WithTags("bgp", "he", "asn")
		assets = append(assets, a)
		if len(assets) >= cfg.MaxAssets {
			return assets, nil
		}
	}
	for _, m := range cidrRE.FindAllStringSubmatch(resp.String(), -1) {
		cidr := m[1]
		a := models.NewAsset().WithTitle(fmt.Sprintf("[BGP.HE] %s", cidr)).
			WithSource(s.Name()).WithTags("bgp", "he", "cidr").WithRaw("cidr", cidr)
		assets = append(assets, a)
		if len(assets) >= cfg.MaxAssets {
			break
		}
	}
	return assets, nil
}
