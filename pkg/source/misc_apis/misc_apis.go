// Package misc_apis aggregates a batch of single-responsibility external API data sources.
// Each source implements source.Source and can be registered as needed in main.go.
package misc_apis

import (
	"context"
	"encoding/base64"
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

// ---------- 公共 helper ----------

func newClient() *req.Client {
	return req.C().SetTimeout(30 * time.Second).SetUserAgent("Ghost/1.0")
}

type baseAPI struct {
	*source.BaseSource
	client *req.Client
}

func newBase(name string) *baseAPI {
	return &baseAPI{BaseSource: source.NewBaseSource(name), client: newClient()}
}

func (b *baseAPI) SetConfig(cfg map[string]any) error { return b.BaseSource.SetConfig(cfg) }

// ---------- 1. CommonCrawl ----------
type CommonCrawl struct{ *baseAPI }

func NewCommonCrawl() *CommonCrawl       { return &CommonCrawl{newBase("commoncrawl")} }
func (s *CommonCrawl) Name() string      { return s.BaseSource.Name() }
func (s *CommonCrawl) Accepts() []string { return []string{"domain"} }
func (s *CommonCrawl) NeedsKey() bool    { return false }
func (s *CommonCrawl) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	cfg := &source.SearchConfig{MaxAssets: 500}
	for _, opt := range opts {
		opt(cfg)
	}
	u := fmt.Sprintf("https://index.commoncrawl.org/CC-MAIN-2024-30-index?url=*.%s&output=json&limit=%d", target, cfg.MaxAssets)
	resp, err := s.client.R().SetContext(ctx).Get(u)
	if err != nil {
		return nil, fmt.Errorf("commoncrawl: %w", err)
	}
	var assets []*models.Asset
	for _, line := range splitLines(resp.String()) {
		if line == "" {
			continue
		}
		urlVal := gjson.Get(line, "url").String()
		if urlVal == "" {
			continue
		}
		assets = append(assets, models.NewAsset().
			WithTitle(fmt.Sprintf("[CommonCrawl] %s", urlVal)).
			WithURL(urlVal).WithSource(s.Name()).WithTags("commoncrawl", "archive"))
		if len(assets) >= cfg.MaxAssets {
			break
		}
	}
	return assets, nil
}

// ---------- 2. DNSlytics ----------
type DNSlytics struct{ *baseAPI }

func NewDNSlytics() *DNSlytics         { return &DNSlytics{newBase("dnslytics")} }
func (s *DNSlytics) Name() string      { return s.BaseSource.Name() }
func (s *DNSlytics) Accepts() []string { return []string{"ip", "domain"} }
func (s *DNSlytics) NeedsKey() bool    { return false }
func (s *DNSlytics) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	u := fmt.Sprintf("https://dnslytics.com/api/v1/ip/%s", target)
	resp, err := s.client.R().SetContext(ctx).Get(u)
	if err != nil {
		return nil, fmt.Errorf("dnslytics: %w", err)
	}
	d := gjson.Parse(resp.String())
	a := models.NewAsset().WithTitle(fmt.Sprintf("[DNSlytics] %s", target)).
		WithIP(target).WithSource(s.Name()).WithTags("dnslytics", "ip").
		WithRaw("asn", d.Get("asn").String()).
		WithRaw("country", d.Get("country").String()).
		WithRaw("isp", d.Get("isp").String())
	return []*models.Asset{a}, nil
}

// ---------- 3. ViewDNS ----------
type ViewDNS struct{ *baseAPI }

func NewViewDNS() *ViewDNS           { return &ViewDNS{newBase("viewdns")} }
func (s *ViewDNS) Name() string      { return s.BaseSource.Name() }
func (s *ViewDNS) Accepts() []string { return []string{"ip", "domain"} }
func (s *ViewDNS) NeedsKey() bool    { return true }
func (s *ViewDNS) SetKey(k string)   { s.BaseSource.SetKey(k) }
func (s *ViewDNS) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	if s.BaseSource.Key() == "" {
		return nil, fmt.Errorf("viewdns needs api key")
	}
	cfg := &source.SearchConfig{MaxAssets: 500}
	for _, opt := range opts {
		opt(cfg)
	}
	u := fmt.Sprintf("https://api.viewdns.info/reverseip/?host=%s&apikey=%s&output=json", target, s.BaseSource.Key())
	resp, err := s.client.R().SetContext(ctx).Get(u)
	if err != nil {
		return nil, fmt.Errorf("viewdns: %w", err)
	}
	var assets []*models.Asset
	for _, item := range gjson.Parse(resp.String()).Get("response.domains").Array() {
		host := item.Get("name").String()
		assets = append(assets, models.NewAsset().WithTitle(fmt.Sprintf("[ViewDNS] %s", host)).
			WithHost(host).WithDomain(host).WithSource(s.Name()).WithTags("viewdns", "reverse"))
		if len(assets) >= cfg.MaxAssets {
			break
		}
	}
	return assets, nil
}

// ---------- 4. Robtex ----------
type Robtex struct{ *baseAPI }

func NewRobtex() *Robtex            { return &Robtex{newBase("robtex")} }
func (s *Robtex) Name() string      { return s.BaseSource.Name() }
func (s *Robtex) Accepts() []string { return []string{"domain", "ip"} }
func (s *Robtex) NeedsKey() bool    { return false }
func (s *Robtex) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	cfg := &source.SearchConfig{MaxAssets: 200}
	for _, opt := range opts {
		opt(cfg)
	}
	u := fmt.Sprintf("https://freeapi.robtex.com/pdns/forward/%s", target)
	resp, err := s.client.R().SetContext(ctx).Get(u)
	if err != nil {
		return nil, fmt.Errorf("robtex: %w", err)
	}
	var assets []*models.Asset
	for _, line := range splitLines(resp.String()) {
		if line == "" {
			continue
		}
		host := gjson.Get(line, "rrname").String()
		ip := gjson.Get(line, "rrdata").String()
		assets = append(assets, models.NewAsset().WithTitle(fmt.Sprintf("[Robtex] %s -> %s", host, ip)).
			WithHost(host).WithDomain(host).WithIP(ip).WithSource(s.Name()).WithTags("robtex", "pdns"))
		if len(assets) >= cfg.MaxAssets {
			break
		}
	}
	return assets, nil
}

// ---------- 5. RIPEstat ----------
type RIPEstat struct{ *baseAPI }

func NewRIPEstat() *RIPEstat          { return &RIPEstat{newBase("ripestat")} }
func (s *RIPEstat) Name() string      { return s.BaseSource.Name() }
func (s *RIPEstat) Accepts() []string { return []string{"ip", "asn"} }
func (s *RIPEstat) NeedsKey() bool    { return false }
func (s *RIPEstat) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	u := fmt.Sprintf("https://stat.ripe.net/data/network-info/data.json?resource=%s", target)
	resp, err := s.client.R().SetContext(ctx).Get(u)
	if err != nil {
		return nil, fmt.Errorf("ripestat: %w", err)
	}
	d := gjson.Parse(resp.String()).Get("data")
	a := models.NewAsset().WithTitle(fmt.Sprintf("[RIPEstat] %s", target)).
		WithIP(target).WithSource(s.Name()).WithTags("ripestat", "ip").
		WithRaw("asns", d.Get("asns").String()).
		WithRaw("prefix", d.Get("prefix").String())
	return []*models.Asset{a}, nil
}

// ---------- 6. RDAP ----------
type RDAP struct{ *baseAPI }

func NewRDAP() *RDAP              { return &RDAP{newBase("rdap")} }
func (s *RDAP) Name() string      { return s.BaseSource.Name() }
func (s *RDAP) Accepts() []string { return []string{"domain", "ip", "asn"} }
func (s *RDAP) NeedsKey() bool    { return false }
func (s *RDAP) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	u := fmt.Sprintf("https://rdap.org/domain/%s", target)
	resp, err := s.client.R().SetContext(ctx).Get(u)
	if err != nil {
		return nil, fmt.Errorf("rdap: %w", err)
	}
	d := gjson.Parse(resp.String())
	a := models.NewAsset().WithTitle(fmt.Sprintf("[RDAP] %s", target)).
		WithDomain(target).WithHost(target).WithSource(s.Name()).WithTags("rdap", "whois").
		WithRaw("handle", d.Get("handle").String()).
		WithRaw("status", d.Get("status").String()).
		WithRaw("nameservers", d.Get("nameservers").String())
	return []*models.Asset{a}, nil
}

// ---------- 7. PublicWWW ----------
type PublicWWW struct{ *baseAPI }

func NewPublicWWW() *PublicWWW         { return &PublicWWW{newBase("publicwww")} }
func (s *PublicWWW) Name() string      { return s.BaseSource.Name() }
func (s *PublicWWW) Accepts() []string { return []string{"keyword"} }
func (s *PublicWWW) NeedsKey() bool    { return true }
func (s *PublicWWW) SetKey(k string)   { s.BaseSource.SetKey(k) }
func (s *PublicWWW) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	if s.BaseSource.Key() == "" {
		return nil, fmt.Errorf("publicwww needs api key")
	}
	cfg := &source.SearchConfig{MaxAssets: 500}
	for _, opt := range opts {
		opt(cfg)
	}
	u := fmt.Sprintf("https://publicwww.com/websites/%%22%s%%22/?export=urls&key=%s", url.QueryEscape(target), s.BaseSource.Key())
	resp, err := s.client.R().SetContext(ctx).Get(u)
	if err != nil {
		return nil, fmt.Errorf("publicwww: %w", err)
	}
	var assets []*models.Asset
	for _, line := range splitLines(resp.String()) {
		if line == "" {
			continue
		}
		assets = append(assets, models.NewAsset().WithTitle(fmt.Sprintf("[PublicWWW] %s", line)).
			WithURL(line).WithSource(s.Name()).WithTags("publicwww", "code"))
		if len(assets) >= cfg.MaxAssets {
			break
		}
	}
	return assets, nil
}

// ---------- 8. Pulsedive ----------
type Pulsedive struct{ *baseAPI }

func NewPulsedive() *Pulsedive         { return &Pulsedive{newBase("pulsedive")} }
func (s *Pulsedive) Name() string      { return s.BaseSource.Name() }
func (s *Pulsedive) Accepts() []string { return []string{"ip", "domain"} }
func (s *Pulsedive) NeedsKey() bool    { return false }
func (s *Pulsedive) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	u := fmt.Sprintf("https://pulsedive.com/api/info.php?indicator=%s", target)
	resp, err := s.client.R().SetContext(ctx).Get(u)
	if err != nil {
		return nil, fmt.Errorf("pulsedive: %w", err)
	}
	d := gjson.Parse(resp.String())
	risk := d.Get("risk").String()
	if risk == "" || risk == "none" {
		return nil, nil
	}
	a := models.NewAsset().WithTitle(fmt.Sprintf("[Pulsedive] %s (%s)", target, risk)).
		WithSource(s.Name()).WithTags("pulsedive", risk).
		WithRaw("indicator", target).WithRaw("risk", risk).
		WithRaw("threats", d.Get("threats").String())
	return []*models.Asset{a}, nil
}

// ---------- 9. PDNS CIRCL ----------
type PDNSCircl struct{ *baseAPI }

func NewPDNSCircl() *PDNSCircl         { return &PDNSCircl{newBase("pdns_circl")} }
func (s *PDNSCircl) Name() string      { return s.BaseSource.Name() }
func (s *PDNSCircl) Accepts() []string { return []string{"domain", "ip"} }
func (s *PDNSCircl) NeedsKey() bool    { return true }
func (s *PDNSCircl) SetKey(k string)   { s.BaseSource.SetKey(k) }
func (s *PDNSCircl) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	if s.BaseSource.Key() == "" {
		return nil, fmt.Errorf("pdns_circl needs api key")
	}
	cfg := &source.SearchConfig{MaxAssets: 500}
	for _, opt := range opts {
		opt(cfg)
	}
	// 需要先对 URL 进行 base64 编码
	rawKey := s.BaseSource.Key()
	authHeader := "Basic " + rawKey
	if strings.Contains(rawKey, ":") {
		authHeader = "Basic " + base64.StdEncoding.EncodeToString([]byte(rawKey))
	}
	u := fmt.Sprintf("https://www.circl.lu/pdns/query/%s", target)
	resp, err := s.client.R().SetContext(ctx).SetHeader("Authorization", authHeader).Get(u)
	if err != nil {
		return nil, fmt.Errorf("pdns_circl: %w", err)
	}
	var assets []*models.Asset
	for _, line := range splitLines(resp.String()) {
		if line == "" {
			continue
		}
		rrname := gjson.Get(line, "rrname").String()
		rdata := gjson.Get(line, "rdata").String()
		assets = append(assets, models.NewAsset().WithTitle(fmt.Sprintf("[CIRCL] %s -> %s", rrname, rdata)).
			WithHost(rrname).WithDomain(rrname).WithSource(s.Name()).WithTags("circl", "pdns").WithRaw("rdata", rdata))
		if len(assets) >= cfg.MaxAssets {
			break
		}
	}
	return assets, nil
}

// ---------- 10. PDNS Mnemonic ----------
type PDNSMnemonic struct{ *baseAPI }

func NewPDNSMnemonic() *PDNSMnemonic      { return &PDNSMnemonic{newBase("pdns_mnemonic")} }
func (s *PDNSMnemonic) Name() string      { return s.BaseSource.Name() }
func (s *PDNSMnemonic) Accepts() []string { return []string{"domain", "ip"} }
func (s *PDNSMnemonic) NeedsKey() bool    { return false }
func (s *PDNSMnemonic) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	cfg := &source.SearchConfig{MaxAssets: 500}
	for _, opt := range opts {
		opt(cfg)
	}
	u := fmt.Sprintf("https://api.mnemonic.no/pdns/v3/%s", target)
	resp, err := s.client.R().SetContext(ctx).Get(u)
	if err != nil {
		return nil, fmt.Errorf("pdns_mnemonic: %w", err)
	}
	var assets []*models.Asset
	for _, item := range gjson.Parse(resp.String()).Get("data").Array() {
		host := item.Get("query").String()
		answer := item.Get("answer").String()
		assets = append(assets, models.NewAsset().WithTitle(fmt.Sprintf("[Mnemonic] %s -> %s", host, answer)).
			WithHost(host).WithDomain(host).WithSource(s.Name()).WithTags("mnemonic", "pdns").WithRaw("answer", answer))
		if len(assets) >= cfg.MaxAssets {
			break
		}
	}
	return assets, nil
}

// ---------- 11. EmailRep ----------
type EmailRep struct{ *baseAPI }

func NewEmailRep() *EmailRep          { return &EmailRep{newBase("emailrep")} }
func (s *EmailRep) Name() string      { return s.BaseSource.Name() }
func (s *EmailRep) Accepts() []string { return []string{"email"} }
func (s *EmailRep) NeedsKey() bool    { return false }
func (s *EmailRep) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	u := fmt.Sprintf("https://emailrep.io/%s", target)
	resp, err := s.client.R().SetContext(ctx).Get(u)
	if err != nil {
		return nil, fmt.Errorf("emailrep: %w", err)
	}
	d := gjson.Parse(resp.String())
	rep := d.Get("reputation").String()
	a := models.NewAsset().WithTitle(fmt.Sprintf("[EmailRep] %s (%s)", target, rep)).
		WithSource(s.Name()).WithTags("emailrep", rep).
		WithRaw("email", target).WithRaw("reputation", rep).
		WithRaw("suspicious", d.Get("suspicious").String()).
		WithRaw("references", d.Get("references").String())
	return []*models.Asset{a}, nil
}

// ---------- 12. HunterIO ----------
type HunterIO struct{ *baseAPI }

func NewHunterIO() *HunterIO          { return &HunterIO{newBase("hunter_io")} }
func (s *HunterIO) Name() string      { return s.BaseSource.Name() }
func (s *HunterIO) Accepts() []string { return []string{"domain"} }
func (s *HunterIO) NeedsKey() bool    { return true }
func (s *HunterIO) SetKey(k string)   { s.BaseSource.SetKey(k) }
func (s *HunterIO) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	if s.BaseSource.Key() == "" {
		return nil, fmt.Errorf("hunter_io needs api key")
	}
	cfg := &source.SearchConfig{MaxAssets: 100}
	for _, opt := range opts {
		opt(cfg)
	}
	u := fmt.Sprintf("https://api.hunter.io/v2/domain-search?domain=%s&api_key=%s&limit=%d", target, s.BaseSource.Key(), cfg.MaxAssets)
	resp, err := s.client.R().SetContext(ctx).Get(u)
	if err != nil {
		return nil, fmt.Errorf("hunter_io: %w", err)
	}
	var assets []*models.Asset
	for _, item := range gjson.Parse(resp.String()).Get("data.emails").Array() {
		email := item.Get("value").String()
		assets = append(assets, models.NewAsset().WithTitle(fmt.Sprintf("[Hunter.io] %s", email)).
			WithSource(s.Name()).WithTags("hunter_io", "email").WithRaw("email", email).
			WithRaw("confidence", item.Get("confidence").String()).
			WithRaw("first_name", item.Get("first_name").String()).
			WithRaw("last_name", item.Get("last_name").String()))
	}
	return assets, nil
}

// ---------- 13. HunterVerify ----------
type HunterVerify struct{ *baseAPI }

func NewHunterVerify() *HunterVerify      { return &HunterVerify{newBase("hunter_verify")} }
func (s *HunterVerify) Name() string      { return s.BaseSource.Name() }
func (s *HunterVerify) Accepts() []string { return []string{"email"} }
func (s *HunterVerify) NeedsKey() bool    { return true }
func (s *HunterVerify) SetKey(k string)   { s.BaseSource.SetKey(k) }
func (s *HunterVerify) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	if s.BaseSource.Key() == "" {
		return nil, fmt.Errorf("hunter_verify needs api key")
	}
	u := fmt.Sprintf("https://api.hunter.io/v2/email-verifier?email=%s&api_key=%s", target, s.BaseSource.Key())
	resp, err := s.client.R().SetContext(ctx).Get(u)
	if err != nil {
		return nil, fmt.Errorf("hunter_verify: %w", err)
	}
	d := gjson.Parse(resp.String()).Get("data")
	a := models.NewAsset().WithTitle(fmt.Sprintf("[HunterVerify] %s (%s)", target, d.Get("status").String())).
		WithSource(s.Name()).WithTags("hunter_verify", d.Get("status").String()).
		WithRaw("email", target).WithRaw("status", d.Get("status").String()).
		WithRaw("score", d.Get("score").String())
	return []*models.Asset{a}, nil
}

// ---------- 14. HudsonRock ----------
type HudsonRock struct{ *baseAPI }

func NewHudsonRock() *HudsonRock        { return &HudsonRock{newBase("hudsonrock")} }
func (s *HudsonRock) Name() string      { return s.BaseSource.Name() }
func (s *HudsonRock) Accepts() []string { return []string{"domain", "email"} }
func (s *HudsonRock) NeedsKey() bool    { return false }
func (s *HudsonRock) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	u := fmt.Sprintf("https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain=%s", target)
	resp, err := s.client.R().SetContext(ctx).Get(u)
	if err != nil {
		return nil, fmt.Errorf("hudsonrock: %w", err)
	}
	d := gjson.Parse(resp.String())
	count := d.Get("total").Int()
	if count == 0 {
		return nil, nil
	}
	a := models.NewAsset().WithTitle(fmt.Sprintf("[HudsonRock] %s (%d stealers)", target, count)).
		WithDomain(target).WithSource(s.Name()).WithTags("hudsonrock", "stealer", "infostealer").
		WithRaw("total", fmt.Sprintf("%d", count)).
		WithRaw("employees", d.Get("employees").String()).
		WithRaw("users", d.Get("users").String())
	return []*models.Asset{a}, nil
}

// ---------- 15. HuntIO ----------
type HuntIO struct{ *baseAPI }

func NewHuntIO() *HuntIO            { return &HuntIO{newBase("hunt_io")} }
func (s *HuntIO) Name() string      { return s.BaseSource.Name() }
func (s *HuntIO) Accepts() []string { return []string{"ip", "domain"} }
func (s *HuntIO) NeedsKey() bool    { return true }
func (s *HuntIO) SetKey(k string)   { s.BaseSource.SetKey(k) }
func (s *HuntIO) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	if s.BaseSource.Key() == "" {
		return nil, fmt.Errorf("hunt_io needs api key")
	}
	u := fmt.Sprintf("https://api.hunt.io/v1/ip/%s", target)
	resp, err := s.client.R().SetContext(ctx).SetHeader("token", s.BaseSource.Key()).Get(u)
	if err != nil {
		return nil, fmt.Errorf("hunt_io: %w", err)
	}
	d := gjson.Parse(resp.String())
	if d.Get("malicious").Bool() {
		a := models.NewAsset().WithTitle(fmt.Sprintf("[Hunt.io] %s (malicious)", target)).
			WithIP(target).WithSource(s.Name()).WithTags("hunt_io", "malicious").
			WithRaw("classifications", d.Get("classifications").String())
		return []*models.Asset{a}, nil
	}
	return nil, nil
}

// ---------- 16. GreyNoiseCommunity ----------
type GreyNoiseCommunity struct{ *baseAPI }

func NewGreyNoiseCommunity() *GreyNoiseCommunity {
	return &GreyNoiseCommunity{newBase("greynoise_community")}
}
func (s *GreyNoiseCommunity) Name() string      { return s.BaseSource.Name() }
func (s *GreyNoiseCommunity) Accepts() []string { return []string{"ip"} }
func (s *GreyNoiseCommunity) NeedsKey() bool    { return false }
func (s *GreyNoiseCommunity) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	u := fmt.Sprintf("https://api.greynoise.io/v3/community/%s", target)
	resp, err := s.client.R().SetContext(ctx).Get(u)
	if err != nil {
		return nil, fmt.Errorf("greynoise_community: %w", err)
	}
	d := gjson.Parse(resp.String())
	cls := d.Get("classification").String()
	if cls == "" || cls == "unknown" {
		return nil, nil
	}
	a := models.NewAsset().WithTitle(fmt.Sprintf("[GreyNoise CE] %s (%s)", target, cls)).
		WithIP(target).WithSource(s.Name()).WithTags("greynoise", cls).
		WithRaw("classification", cls).WithRaw("name", d.Get("name").String())
	return []*models.Asset{a}, nil
}

// ---------- 17. GitHubCommits ----------
type GitHubCommits struct{ *baseAPI }

func NewGitHubCommits() *GitHubCommits     { return &GitHubCommits{newBase("github_commits")} }
func (s *GitHubCommits) Name() string      { return s.BaseSource.Name() }
func (s *GitHubCommits) Accepts() []string { return []string{"keyword", "domain"} }
func (s *GitHubCommits) NeedsKey() bool    { return true }
func (s *GitHubCommits) SetKey(k string)   { s.BaseSource.SetKey(k) }
func (s *GitHubCommits) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	cfg := &source.SearchConfig{MaxAssets: 50}
	for _, opt := range opts {
		opt(cfg)
	}
	u := fmt.Sprintf("https://api.github.com/search/commits?q=%s&per_page=%d", url.QueryEscape(target), cfg.MaxAssets)
	resp, err := s.client.R().SetContext(ctx).
		SetHeader("Authorization", "token "+s.BaseSource.Key()).
		SetHeader("Accept", "application/vnd.github.cloak-preview").Get(u)
	if err != nil {
		return nil, fmt.Errorf("github_commits: %w", err)
	}
	var assets []*models.Asset
	for _, item := range gjson.Parse(resp.String()).Get("items").Array() {
		urlVal := item.Get("html_url").String()
		repo := item.Get("repository.full_name").String()
		msg := item.Get("commit.message").String()
		assets = append(assets, models.NewAsset().WithTitle(fmt.Sprintf("[GitCommit] %s: %s", repo, msg)).
			WithURL(urlVal).WithSource(s.Name()).WithTags("github", "commit").
			WithRaw("repo", repo).WithRaw("message", msg))
		if len(assets) >= cfg.MaxAssets {
			break
		}
	}
	return assets, nil
}

// ---------- 18. Driftnet ----------
type Driftnet struct{ *baseAPI }

func NewDriftnet() *Driftnet          { return &Driftnet{newBase("driftnet")} }
func (s *Driftnet) Name() string      { return s.BaseSource.Name() }
func (s *Driftnet) Accepts() []string { return []string{"domain", "ip"} }
func (s *Driftnet) NeedsKey() bool    { return true }
func (s *Driftnet) SetKey(k string)   { s.BaseSource.SetKey(k) }
func (s *Driftnet) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	cfg := &source.SearchConfig{MaxAssets: 200}
	for _, opt := range opts {
		opt(cfg)
	}
	u := fmt.Sprintf("https://api.driftnet.io/v1/domain/scan?host=%s", target)
	resp, err := s.client.R().SetContext(ctx).SetHeader("Authorization", "Bearer "+s.BaseSource.Key()).Get(u)
	if err != nil {
		return nil, fmt.Errorf("driftnet: %w", err)
	}
	var assets []*models.Asset
	for _, item := range gjson.Parse(resp.String()).Get("results").Array() {
		host := item.Get("host").String()
		ip := item.Get("ip").String()
		assets = append(assets, models.NewAsset().WithTitle(fmt.Sprintf("[Driftnet] %s", host)).
			WithHost(host).WithDomain(host).WithIP(ip).WithSource(s.Name()).WithTags("driftnet", "scan"))
		if len(assets) >= cfg.MaxAssets {
			break
		}
	}
	return assets, nil
}

// ---------- 19. DDoSecrets ----------
type DDoSecrets struct{ *baseAPI }

func NewDDoSecrets() *DDoSecrets        { return &DDoSecrets{newBase("ddosecrets")} }
func (s *DDoSecrets) Name() string      { return s.BaseSource.Name() }
func (s *DDoSecrets) Accepts() []string { return []string{"keyword", "domain"} }
func (s *DDoSecrets) NeedsKey() bool    { return false }
func (s *DDoSecrets) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	u := fmt.Sprintf("https://ddosecrets.com/wiki/Special:Search?search=%s", url.QueryEscape(target))
	resp, err := s.client.R().SetContext(ctx).Get(u)
	if err != nil {
		return nil, fmt.Errorf("ddosecrets: %w", err)
	}
	titleRE := regexp.MustCompile(`<a[^>]+title="([^"]+)"[^>]+data-serp-pos="\d+">`)
	var assets []*models.Asset
	for _, m := range titleRE.FindAllStringSubmatch(resp.String(), -1) {
		title := m[1]
		assets = append(assets, models.NewAsset().WithTitle(fmt.Sprintf("[DDoSecrets] %s", title)).
			WithSource(s.Name()).WithTags("ddosecrets", "leak", "public-index").WithRaw("title", title))
	}
	return assets, nil
}

// ---------- 20. BreachDirectory ----------
type BreachDirectory struct{ *baseAPI }

func NewBreachDirectory() *BreachDirectory   { return &BreachDirectory{newBase("breachdirectory")} }
func (s *BreachDirectory) Name() string      { return s.BaseSource.Name() }
func (s *BreachDirectory) Accepts() []string { return []string{"email", "domain"} }
func (s *BreachDirectory) NeedsKey() bool    { return true }
func (s *BreachDirectory) SetKey(k string)   { s.BaseSource.SetKey(k) }
func (s *BreachDirectory) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	u := fmt.Sprintf("https://breachdirectory.p.rapidapi.com/?func=auto&term=%s", target)
	resp, err := s.client.R().SetContext(ctx).
		SetHeader("X-RapidAPI-Key", s.BaseSource.Key()).
		SetHeader("X-RapidAPI-Host", "breachdirectory.p.rapidapi.com").Get(u)
	if err != nil {
		return nil, fmt.Errorf("breachdirectory: %w", err)
	}
	var assets []*models.Asset
	for _, item := range gjson.Parse(resp.String()).Get("result").Array() {
		src := item.Get("sources").String()
		password := item.Get("password").String()
		assets = append(assets, models.NewAsset().WithTitle(fmt.Sprintf("[BreachDir] %s @ %s", target, src)).
			WithSource(s.Name()).WithTags("breach", "public-index").
			WithRaw("source", src).WithRaw("password_hint", maskString(password)))
	}
	return assets, nil
}

// ---------- helpers ----------

func splitLines(s string) []string {
	var out []string
	start := 0
	for i, c := range s {
		if c == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	out = append(out, s[start:])
	return out
}

func maskString(s string) string {
	if len(s) <= 2 {
		return "**"
	}
	return s[:2] + "****"
}
