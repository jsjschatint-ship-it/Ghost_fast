package hackertarget

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/imroc/req/v3"

	"github.com/wgpsec/ENScan/pkg/models"
	"github.com/wgpsec/ENScan/pkg/source"
)

// baseURL is the production HackerTarget API root. Tests override it via
// SetBaseURL to point at httptest.
const baseURL = "https://api.hackertarget.com"

// HackerTarget queries the public HackerTarget API. No API key required (free
// tier allows ~100 calls per day per IP — beyond that the API returns a
// plaintext "API count exceeded" message with HTTP 200, which we detect).
//
// Three endpoints are wired:
//
//	hostsearch       /hostsearch/?q=<domain>        →  "<host>,<ip>" lines
//	reverseiplookup  /reverseiplookup/?q=<ip>       →  one host per line
//	findshareddns    /findshareddns/?q=<ip>         →  one host per line
//
// Inputs are dispatched by target type:
//   - domain → hostsearch
//   - ip     → reverseiplookup + findshareddns
type HackerTarget struct {
	*source.BaseSource
	client  *req.Client
	baseURL string
}

// NewHackerTarget constructs a default-configured source.
func NewHackerTarget() *HackerTarget {
	s := &HackerTarget{
		BaseSource: source.NewBaseSource("hackertarget"),
		baseURL:    baseURL,
	}
	s.buildClient()
	return s
}

// Name returns the source name (delegated to BaseSource).
func (s *HackerTarget) Name() string {
	return s.BaseSource.Name()
}

// Accepts 接受的输入类型
func (s *HackerTarget) Accepts() []string {
	return []string{"domain", "ip"}
}

// NeedsKey 是否需要 API Key
// free tier does not, so we return false.
func (s *HackerTarget) NeedsKey() bool {
	return false
}

// SetConfig accepts arbitrary config (none used today) and rebuilds the
// HTTP client so timeout/UA tweaks take effect.
func (s *HackerTarget) SetConfig(cfg map[string]any) error {
	_ = s.BaseSource.SetConfig(cfg)
	s.buildClient()
	return nil
}

// SetBaseURL overrides the API root. Used by tests; safe to call at runtime.
func (s *HackerTarget) SetBaseURL(u string) { s.baseURL = u }

// buildClient 构建 HTTP 客户端
func (s *HackerTarget) buildClient() {
	s.client = req.C().
		SetTimeout(30 * time.Second).
		SetUserAgent("Mozilla/5.0 (compatible; Ghost/1.0)")
}

// Search runs the configured queries against `target`. The kind of queries
// dispatched depends on whether `target` looks like an IP or a domain.
func (s *HackerTarget) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	cfg := &source.SearchConfig{MaxAssets: 100}
	for _, opt := range opts {
		opt(cfg)
	}

	target = strings.TrimSpace(target)
	if target == "" {
		return nil, fmt.Errorf("hackertarget: empty target")
	}

	var allAssets []*models.Asset
	if isIP(target) {
		// IP path: reverse DNS + shared DNS
		if assets, err := s.reverseDNS(ctx, target); err == nil {
			allAssets = append(allAssets, assets...)
		}
		if assets, err := s.sharedHosts(ctx, target); err == nil {
			allAssets = append(allAssets, assets...)
		}
	} else {
		// Domain path: subdomain enumeration via hostsearch
		if assets, err := s.hostSearch(ctx, target); err == nil {
			allAssets = append(allAssets, assets...)
		}
	}

	if cfg.MaxAssets > 0 && len(allAssets) > cfg.MaxAssets {
		allAssets = allAssets[:cfg.MaxAssets]
	}
	return allAssets, nil
}

// hostSearch enumerates subdomains via /hostsearch (CSV: host,ip per line).
func (s *HackerTarget) hostSearch(ctx context.Context, domain string) ([]*models.Asset, error) {
	body, err := s.fetchPlain(ctx, fmt.Sprintf("%s/hostsearch/?q=%s", s.baseURL, domain))
	if err != nil {
		return nil, err
	}
	var assets []*models.Asset
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		host, ip, _ := strings.Cut(line, ",")
		host = strings.TrimSpace(host)
		ip = strings.TrimSpace(ip)
		if host == "" {
			continue
		}
		a := models.NewAsset().
			WithTitle(fmt.Sprintf("[HackerTarget] %s", host)).
			WithHost(host).
			WithDomain(host).
			WithSource(s.Name()).
			WithTags("subdomain", "hackertarget").
			WithRaw("type", "subdomain")
		if ip != "" {
			a.WithIP(ip)
		}
		assets = append(assets, a)
	}
	return assets, nil
}

// reverseDNS fetches /reverseiplookup → hosts pointing at the given IP.
func (s *HackerTarget) reverseDNS(ctx context.Context, ip string) ([]*models.Asset, error) {
	body, err := s.fetchPlain(ctx, fmt.Sprintf("%s/reverseiplookup/?q=%s", s.baseURL, ip))
	if err != nil {
		return nil, err
	}
	return s.makeHostAssets(body, ip, "reverse_dns", []string{"reverse", "dns"}), nil
}

// sharedHosts fetches /findshareddns → other hosts that share the IP's NS.
func (s *HackerTarget) sharedHosts(ctx context.Context, ip string) ([]*models.Asset, error) {
	body, err := s.fetchPlain(ctx, fmt.Sprintf("%s/findshareddns/?q=%s", s.baseURL, ip))
	if err != nil {
		return nil, err
	}
	return s.makeHostAssets(body, ip, "shared_host", []string{"shared", "dns"}), nil
}

// makeHostAssets is shared between reverseDNS + sharedHosts: one host per
// line, attach the source IP and the supplied tags.
func (s *HackerTarget) makeHostAssets(body, sourceIP, kind string, tags []string) []*models.Asset {
	var assets []*models.Asset
	for _, line := range strings.Split(body, "\n") {
		host := strings.TrimSpace(line)
		if host == "" {
			continue
		}
		a := models.NewAsset().
			WithTitle(fmt.Sprintf("[HackerTarget] %s", host)).
			WithHost(host).
			WithDomain(host).
			WithIP(sourceIP).
			WithSource(s.Name()).
			WithTags(tags...).
			WithRaw("type", kind)
		assets = append(assets, a)
	}
	return assets
}

// fetchPlain performs a GET, validates the response, and converts the
// HackerTarget rate-limit/error sentinels into a Go error.
func (s *HackerTarget) fetchPlain(ctx context.Context, url string) (string, error) {
	resp, err := s.client.R().SetContext(ctx).Get(url)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("hackertarget: status %d", resp.StatusCode)
	}
	body := resp.String()
	low := strings.ToLower(strings.TrimSpace(body))
	// HackerTarget signals errors with 200 + plaintext sentinels.
	switch {
	case strings.HasPrefix(low, "api count exceeded"):
		return "", fmt.Errorf("hackertarget: rate limit (free tier 100/day)")
	case strings.HasPrefix(low, "error"):
		return "", fmt.Errorf("hackertarget: %s", strings.TrimSpace(body))
	case strings.HasPrefix(low, "no dns"), strings.HasPrefix(low, "no records"):
		// Empty result, not an error — return empty body so callers parse 0 lines.
		return "", nil
	}
	return body, nil
}

// isIP reports whether s parses as an IPv4 or IPv6 literal.
func isIP(s string) bool { return net.ParseIP(s) != nil }
