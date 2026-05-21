package rapiddns

import (
	"context"
	"fmt"
	"regexp"
	"time"

	"github.com/imroc/req/v3"
	"github.com/wgpsec/ENScan/pkg/models"
	"github.com/wgpsec/ENScan/pkg/source"
)

type RapidDNS struct {
	*source.BaseSource
	client *req.Client
}

func NewRapidDNS() *RapidDNS {
	s := &RapidDNS{BaseSource: source.NewBaseSource("rapiddns")}
	s.client = req.C().SetTimeout(30 * time.Second).SetUserAgent("Mozilla/5.0")
	return s
}

func (s *RapidDNS) Name() string                       { return s.BaseSource.Name() }
func (s *RapidDNS) Accepts() []string                  { return []string{"domain"} }
func (s *RapidDNS) NeedsKey() bool                     { return false }
func (s *RapidDNS) SetConfig(cfg map[string]any) error { return s.BaseSource.SetConfig(cfg) }

func (s *RapidDNS) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	cfg := &source.SearchConfig{MaxAssets: 500}
	for _, opt := range opts {
		opt(cfg)
	}
	u := fmt.Sprintf("https://rapiddns.io/subdomain/%s?full=1", target)
	resp, err := s.client.R().SetContext(ctx).Get(u)
	if err != nil {
		return nil, fmt.Errorf("rapiddns: %w", err)
	}
	// 解析 HTML 表格中的子域名
	re := regexp.MustCompile(`<td>([a-zA-Z0-9.\-]+\.` + regexp.QuoteMeta(target) + `)</td>`)
	matches := re.FindAllStringSubmatch(resp.String(), -1)
	seen := make(map[string]bool)
	var assets []*models.Asset
	for _, m := range matches {
		host := m[1]
		if seen[host] {
			continue
		}
		seen[host] = true
		a := models.NewAsset().WithTitle(fmt.Sprintf("[RapidDNS] %s", host)).
			WithHost(host).WithDomain(host).WithSource(s.Name()).WithTags("subdomain", "rapiddns")
		assets = append(assets, a)
		if len(assets) >= cfg.MaxAssets {
			break
		}
	}
	return assets, nil
}
