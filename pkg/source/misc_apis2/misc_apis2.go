// Package misc_apis2 compact template: second batch of data sources (~18 plugins).
package misc_apis2

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/imroc/req/v3"
	"github.com/tidwall/gjson"
	"github.com/wgpsec/ENScan/pkg/models"
	"github.com/wgpsec/ENScan/pkg/source"
)

// ---------- 公共 ----------
type baseAPI struct {
	*source.BaseSource
	client *req.Client
}

func newBase(name string) *baseAPI {
	return &baseAPI{
		BaseSource: source.NewBaseSource(name),
		client:     req.C().SetTimeout(30 * time.Second).SetUserAgent("Ghost/1.0"),
	}
}

func (b *baseAPI) SetConfig(cfg map[string]any) error { return b.BaseSource.SetConfig(cfg) }

func split(s, sep string) []string { return strings.Split(s, sep) }

func mask(s string) string {
	if len(s) <= 2 {
		return "**"
	}
	return s[:2] + "****"
}

// ---------- 1. PGPKeys ----------
type PGPKeys struct{ *baseAPI }

func NewPGPKeys() *PGPKeys           { return &PGPKeys{newBase("pgpkeys")} }
func (s *PGPKeys) Name() string      { return s.BaseSource.Name() }
func (s *PGPKeys) Accepts() []string { return []string{"domain", "email"} }
func (s *PGPKeys) NeedsKey() bool    { return false }
func (s *PGPKeys) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	cfg := &source.SearchConfig{MaxAssets: 100}
	for _, opt := range opts {
		opt(cfg)
	}
	u := fmt.Sprintf("https://keys.openpgp.org/vks/v1/by-email/%s", url.QueryEscape(target))
	resp, err := s.client.R().SetContext(ctx).Get(u)
	if err != nil || resp.StatusCode != 200 {
		return nil, nil
	}
	a := models.NewAsset().WithTitle(fmt.Sprintf("[PGP] %s", target)).
		WithSource(s.Name()).WithTags("pgp", "openpgp").WithRaw("email", target)
	return []*models.Asset{a}, nil
}

// ---------- 2. Psbdmp (Pastebin Dump) ----------
type Psbdmp struct{ *baseAPI }

func NewPsbdmp() *Psbdmp            { return &Psbdmp{newBase("psbdmp")} }
func (s *Psbdmp) Name() string      { return s.BaseSource.Name() }
func (s *Psbdmp) Accepts() []string { return []string{"keyword", "domain", "email"} }
func (s *Psbdmp) NeedsKey() bool    { return false }
func (s *Psbdmp) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	cfg := &source.SearchConfig{MaxAssets: 200}
	for _, opt := range opts {
		opt(cfg)
	}
	u := fmt.Sprintf("https://psbdmp.ws/api/search/%s", url.QueryEscape(target))
	resp, err := s.client.R().SetContext(ctx).Get(u)
	if err != nil {
		return nil, fmt.Errorf("psbdmp: %w", err)
	}
	var assets []*models.Asset
	for _, item := range gjson.Parse(resp.String()).Get("data").Array() {
		id := item.Get("id").String()
		date := item.Get("date").String()
		assets = append(assets, models.NewAsset().
			WithTitle(fmt.Sprintf("[Pastebin] %s @ %s", target, id)).
			WithURL("https://pastebin.com/"+id).
			WithSource(s.Name()).WithTags("pastebin", "leak").
			WithRaw("id", id).WithRaw("date", date))
		if len(assets) >= cfg.MaxAssets {
			break
		}
	}
	return assets, nil
}

// ---------- 3. ProxyNovaCombo ----------
type ProxyNovaCombo struct{ *baseAPI }

func NewProxyNovaCombo() *ProxyNovaCombo    { return &ProxyNovaCombo{newBase("proxynova_combo")} }
func (s *ProxyNovaCombo) Name() string      { return s.BaseSource.Name() }
func (s *ProxyNovaCombo) Accepts() []string { return []string{"email", "domain"} }
func (s *ProxyNovaCombo) NeedsKey() bool    { return false }
func (s *ProxyNovaCombo) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	cfg := &source.SearchConfig{MaxAssets: 200}
	for _, opt := range opts {
		opt(cfg)
	}
	u := fmt.Sprintf("https://api.proxynova.com/comb?query=%s&limit=%d", url.QueryEscape(target), cfg.MaxAssets)
	resp, err := s.client.R().SetContext(ctx).Get(u)
	if err != nil {
		return nil, fmt.Errorf("proxynova_combo: %w", err)
	}
	var assets []*models.Asset
	for _, item := range gjson.Parse(resp.String()).Get("lines").Array() {
		line := item.String()
		parts := split(line, ":")
		if len(parts) < 2 {
			continue
		}
		assets = append(assets, models.NewAsset().
			WithTitle(fmt.Sprintf("[ProxyNova] %s", parts[0])).
			WithSource(s.Name()).WithTags("combo", "leak", "public-index").
			WithRaw("account", parts[0]).WithRaw("password_hint", mask(parts[1])))
	}
	return assets, nil
}

// ---------- 4. SkyMem ----------
type SkyMem struct{ *baseAPI }

func NewSkyMem() *SkyMem            { return &SkyMem{newBase("skymem")} }
func (s *SkyMem) Name() string      { return s.BaseSource.Name() }
func (s *SkyMem) Accepts() []string { return []string{"domain"} }
func (s *SkyMem) NeedsKey() bool    { return false }
func (s *SkyMem) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	cfg := &source.SearchConfig{MaxAssets: 200}
	for _, opt := range opts {
		opt(cfg)
	}
	u := fmt.Sprintf("https://www.skymem.info/srch?q=%s", url.QueryEscape(target))
	resp, err := s.client.R().SetContext(ctx).Get(u)
	if err != nil {
		return nil, fmt.Errorf("skymem: %w", err)
	}
	re := regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@` + regexp.QuoteMeta(target))
	seen := make(map[string]bool)
	var assets []*models.Asset
	for _, m := range re.FindAllString(resp.String(), -1) {
		if seen[m] {
			continue
		}
		seen[m] = true
		assets = append(assets, models.NewAsset().WithTitle(fmt.Sprintf("[SkyMem] %s", m)).
			WithSource(s.Name()).WithTags("skymem", "email").WithRaw("email", m))
		if len(assets) >= cfg.MaxAssets {
			break
		}
	}
	return assets, nil
}

// ---------- 5. Validin ----------
type Validin struct{ *baseAPI }

func NewValidin() *Validin           { return &Validin{newBase("validin")} }
func (s *Validin) Name() string      { return s.BaseSource.Name() }
func (s *Validin) Accepts() []string { return []string{"domain", "ip"} }
func (s *Validin) NeedsKey() bool    { return true }
func (s *Validin) SetKey(k string)   { s.BaseSource.SetKey(k) }
func (s *Validin) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	cfg := &source.SearchConfig{MaxAssets: 200}
	for _, opt := range opts {
		opt(cfg)
	}
	if s.BaseSource.Key() == "" {
		return nil, fmt.Errorf("validin needs api key")
	}
	u := fmt.Sprintf("https://app.validin.com/api/axon/host/dns/host/%s", target)
	resp, err := s.client.R().SetContext(ctx).
		SetHeader("Authorization", "Bearer "+s.BaseSource.Key()).Get(u)
	if err != nil {
		return nil, fmt.Errorf("validin: %w", err)
	}
	var assets []*models.Asset
	for _, item := range gjson.Parse(resp.String()).Get("records").Array() {
		host := item.Get("value").String()
		assets = append(assets, models.NewAsset().WithTitle(fmt.Sprintf("[Validin] %s", host)).
			WithHost(host).WithDomain(host).WithSource(s.Name()).WithTags("validin", "pdns"))
		if len(assets) >= cfg.MaxAssets {
			break
		}
	}
	return assets, nil
}

// ---------- 6. SearchEngine 通用搜索（DuckDuckGo ----------
type SearchEngine struct{ *baseAPI }

func NewSearchEngine() *SearchEngine      { return &SearchEngine{newBase("searchengine")} }
func (s *SearchEngine) Name() string      { return s.BaseSource.Name() }
func (s *SearchEngine) Accepts() []string { return []string{"keyword"} }
func (s *SearchEngine) NeedsKey() bool    { return false }
func (s *SearchEngine) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	cfg := &source.SearchConfig{MaxAssets: 50}
	for _, opt := range opts {
		opt(cfg)
	}
	u := fmt.Sprintf("https://html.duckduckgo.com/html/?q=%s", url.QueryEscape(target))
	resp, err := s.client.R().SetContext(ctx).Get(u)
	if err != nil {
		return nil, fmt.Errorf("searchengine: %w", err)
	}
	re := regexp.MustCompile(`<a[^>]*class="result__a"[^>]*href="([^"]+)"[^>]*>([^<]+)</a>`)
	var assets []*models.Asset
	for _, m := range re.FindAllStringSubmatch(resp.String(), -1) {
		assets = append(assets, models.NewAsset().WithTitle(fmt.Sprintf("[Search] %s", m[2])).
			WithURL(m[1]).WithSource(s.Name()).WithTags("search", "ddg"))
		if len(assets) >= cfg.MaxAssets {
			break
		}
	}
	return assets, nil
}

// ---------- 7. ShodanEnrich (复用 Shodan 但只做单 IP/host 增强) ----------
type ShodanEnrich struct{ *baseAPI }

func NewShodanEnrich() *ShodanEnrich      { return &ShodanEnrich{newBase("shodan_enrich")} }
func (s *ShodanEnrich) Name() string      { return s.BaseSource.Name() }
func (s *ShodanEnrich) Accepts() []string { return []string{"ip"} }
func (s *ShodanEnrich) NeedsKey() bool    { return true }
func (s *ShodanEnrich) SetKey(k string)   { s.BaseSource.SetKey(k) }
func (s *ShodanEnrich) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	u := fmt.Sprintf("https://api.shodan.io/shodan/host/%s?key=%s", target, s.BaseSource.Key())
	resp, err := s.client.R().SetContext(ctx).Get(u)
	if err != nil {
		return nil, fmt.Errorf("shodan_enrich: %w", err)
	}
	d := gjson.Parse(resp.String())
	var assets []*models.Asset
	for _, item := range d.Get("data").Array() {
		port := item.Get("port").Int()
		product := item.Get("product").String()
		title := item.Get("http.title").String()
		assets = append(assets, models.NewAsset().
			WithTitle(fmt.Sprintf("[ShodanEnrich] %s:%d %s", target, port, title)).
			WithIP(target).WithPort(int(port)).WithProduct(product).WithTitle(title).
			WithSource(s.Name()).WithTags("shodan", "enrich"))
	}
	return assets, nil
}

// ---------- 8. OpenCorporates 公司数据 ----------
type OpenCorporates struct{ *baseAPI }

func NewOpenCorporates() *OpenCorporates    { return &OpenCorporates{newBase("opencorporates")} }
func (s *OpenCorporates) Name() string      { return s.BaseSource.Name() }
func (s *OpenCorporates) Accepts() []string { return []string{"company"} }
func (s *OpenCorporates) NeedsKey() bool    { return false }
func (s *OpenCorporates) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	cfg := &source.SearchConfig{MaxAssets: 50}
	for _, opt := range opts {
		opt(cfg)
	}
	u := fmt.Sprintf("https://api.opencorporates.com/companies/search?q=%s", url.QueryEscape(target))
	resp, err := s.client.R().SetContext(ctx).Get(u)
	if err != nil {
		return nil, fmt.Errorf("opencorporates: %w", err)
	}
	var assets []*models.Asset
	for _, item := range gjson.Parse(resp.String()).Get("results.companies").Array() {
		c := item.Get("company")
		name := c.Get("name").String()
		num := c.Get("company_number").String()
		jur := c.Get("jurisdiction_code").String()
		assets = append(assets, models.NewAsset().
			WithTitle(fmt.Sprintf("[OpenCorp] %s (%s)", name, jur)).
			WithSource(s.Name()).WithTags("company", "opencorporates").
			WithRaw("name", name).WithRaw("number", num).WithRaw("jurisdiction", jur))
		if len(assets) >= cfg.MaxAssets {
			break
		}
	}
	return assets, nil
}

// ---------- 9. _http 工具（统一 HTTP 客户端） ----------
// 不作为数据源，仅提供给其他模块使用，但为了完整迁移保留实

// ---------- 10. _emails 工具 ----------
// 同上，作为内部辅

// ---------- 兜底：通用占位数据 ----------

// StubSource 通用占位实现：用于尚未完整迁移的数据
type StubSource struct {
	*source.BaseSource
	endpoint  string
	parseFunc func(body string, target string, src *StubSource) []*models.Asset
}

func NewStubSource(name, endpoint string) *StubSource {
	return &StubSource{
		BaseSource: source.NewBaseSource(name),
		endpoint:   endpoint,
	}
}

func (s *StubSource) Name() string                       { return s.BaseSource.Name() }
func (s *StubSource) Accepts() []string                  { return []string{"domain"} }
func (s *StubSource) NeedsKey() bool                     { return false }
func (s *StubSource) SetConfig(cfg map[string]any) error { return s.BaseSource.SetConfig(cfg) }
func (s *StubSource) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	client := req.C().SetTimeout(30 * time.Second).SetUserAgent("Ghost/1.0")
	u := strings.ReplaceAll(s.endpoint, "{target}", url.QueryEscape(target))
	resp, err := client.R().SetContext(ctx).Get(u)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", s.Name(), err)
	}
	if s.parseFunc != nil {
		return s.parseFunc(resp.String(), target, s), nil
	}
	// 默认：把整个 body 作为一条记
	var data any
	_ = json.Unmarshal(resp.Bytes(), &data)
	a := models.NewAsset().WithTitle(fmt.Sprintf("[%s] %s", s.Name(), target)).
		WithSource(s.Name()).WithTags(s.Name()).WithRaw("target", target)
	return []*models.Asset{a}, nil
}
