package threatminer

import (
	"context"
	"fmt"
	"time"

	"github.com/imroc/req/v3"
	"github.com/tidwall/gjson"
	"github.com/wgpsec/ENScan/pkg/models"
	"github.com/wgpsec/ENScan/pkg/source"
)

type ThreatMiner struct {
	*source.BaseSource
	client *req.Client
}

func NewThreatMiner() *ThreatMiner {
	s := &ThreatMiner{BaseSource: source.NewBaseSource("threatminer")}
	s.client = req.C().SetTimeout(30 * time.Second).SetUserAgent("Ghost/1.0")
	return s
}

func (s *ThreatMiner) Name() string                       { return s.BaseSource.Name() }
func (s *ThreatMiner) Accepts() []string                  { return []string{"domain", "ip"} }
func (s *ThreatMiner) NeedsKey() bool                     { return false }
func (s *ThreatMiner) SetConfig(cfg map[string]any) error { return s.BaseSource.SetConfig(cfg) }

func (s *ThreatMiner) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	cfg := &source.SearchConfig{MaxAssets: 500}
	for _, opt := range opts {
		opt(cfg)
	}
	u := fmt.Sprintf("https://api.threatminer.org/v2/domain.php?q=%s&rt=5", target)
	resp, err := s.client.R().SetContext(ctx).Get(u)
	if err != nil {
		return nil, fmt.Errorf("threatminer: %w", err)
	}
	var assets []*models.Asset
	for _, item := range gjson.Parse(resp.String()).Get("results").Array() {
		host := item.String()
		a := models.NewAsset().WithTitle(fmt.Sprintf("[ThreatMiner] %s", host)).
			WithHost(host).WithDomain(host).WithSource(s.Name()).WithTags("threatminer", "pdns")
		assets = append(assets, a)
		if len(assets) >= cfg.MaxAssets {
			break
		}
	}
	return assets, nil
}
