package chinaz

import (
	"context"
	"fmt"
	"regexp"
	"time"

	"github.com/imroc/req/v3"
	"github.com/wgpsec/ENScan/pkg/models"
	"github.com/wgpsec/ENScan/pkg/source"
)

// Chinaz 通过站长之家查询域名信息
type Chinaz struct {
	*source.BaseSource
	client *req.Client
}

func NewChinaz() *Chinaz {
	s := &Chinaz{BaseSource: source.NewBaseSource("chinaz")}
	s.client = req.C().SetTimeout(30 * time.Second).SetUserAgent("Mozilla/5.0")
	return s
}

func (s *Chinaz) Name() string                       { return s.BaseSource.Name() }
func (s *Chinaz) Accepts() []string                  { return []string{"domain"} }
func (s *Chinaz) NeedsKey() bool                     { return false }
func (s *Chinaz) SetConfig(cfg map[string]any) error { return s.BaseSource.SetConfig(cfg) }

func (s *Chinaz) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	cfg := &source.SearchConfig{MaxAssets: 200}
	for _, opt := range opts {
		opt(cfg)
	}
	u := fmt.Sprintf("https://alexa.chinaz.com/%s", target)
	resp, err := s.client.R().SetContext(ctx).Get(u)
	if err != nil {
		return nil, fmt.Errorf("chinaz: %w", err)
	}
	re := regexp.MustCompile(`<a[^>]+>([a-zA-Z0-9.\-]+\.` + regexp.QuoteMeta(target) + `)</a>`)
	seen := make(map[string]bool)
	var assets []*models.Asset
	for _, m := range re.FindAllStringSubmatch(resp.String(), -1) {
		host := m[1]
		if seen[host] {
			continue
		}
		seen[host] = true
		a := models.NewAsset().WithTitle(fmt.Sprintf("[Chinaz] %s", host)).
			WithHost(host).WithDomain(host).WithSource(s.Name()).WithTags("subdomain", "chinaz")
		assets = append(assets, a)
		if len(assets) >= cfg.MaxAssets {
			break
		}
	}
	return assets, nil
}
