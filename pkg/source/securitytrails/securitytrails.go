package securitytrails

// SecurityTrails - 子域 + DNS 历史精品（每月免费额度）。
// 三步：
//   1) GET /v1/domain/<d>/subdomains?children_only=false&include_inactive=true
//   2) GET /v1/domain/<d>                   -> current_dns.a.values[*].ip
//   3) GET /v1/history/<d>/dns/a            -> 历史 A 记录（找 CDN 前真实 IP）
// Auth: APIKEY: <key>

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/imroc/req/v3"
	"github.com/tidwall/gjson"
	"github.com/wgpsec/ENScan/pkg/models"
	"github.com/wgpsec/ENScan/pkg/source"
)

const stBase = "https://api.securitytrails.com/v1"

type SecurityTrails struct {
	*source.BaseSource
	client *req.Client
}

func NewSecurityTrails() *SecurityTrails {
	return &SecurityTrails{
		BaseSource: source.NewBaseSource("securitytrails"),
		client:     req.C().SetTimeout(30 * time.Second).SetUserAgent("Ghost/1.0"),
	}
}

func (s *SecurityTrails) Name() string      { return s.BaseSource.Name() }
func (s *SecurityTrails) Accepts() []string { return []string{"domain"} }
func (s *SecurityTrails) NeedsKey() bool    { return true }

func (s *SecurityTrails) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	cfg := &source.SearchConfig{MaxAssets: 2000}
	for _, opt := range opts {
		opt(cfg)
	}
	if target == "" || !strings.Contains(target, ".") {
		return nil, nil
	}
	key := s.BaseSource.Key()
	if key == "" {
		return nil, fmt.Errorf("securitytrails needs api key")
	}
	domain := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(target), "."))

	headers := map[string]string{
		"APIKEY": key,
		"Accept": "application/json",
	}

	out := make([]*models.Asset, 0, 256)
	seen := make(map[string]struct{}, 512)
	add := func(a *models.Asset) bool {
		k := fmt.Sprintf("%s|%s|%s", a.IP, a.Host, strings.Join(a.Tags, ","))
		if _, ok := seen[k]; ok {
			return true
		}
		seen[k] = struct{}{}
		out = append(out, a)
		return cfg.MaxAssets <= 0 || len(out) < cfg.MaxAssets
	}

	// 1) 子域
	{
		resp, err := s.client.R().
			SetContext(ctx).
			SetHeaders(headers).
			SetQueryParams(map[string]string{
				"children_only":    "false",
				"include_inactive": "true",
			}).
			Get(stBase + "/domain/" + domain + "/subdomains")
		if err == nil && resp.StatusCode == 200 {
			for _, sub := range gjson.Parse(resp.String()).Get("subdomains").Array() {
				full := strings.ToLower(sub.String() + "." + domain)
				a := models.NewAsset().
					WithDomain(full).WithHost(full).
					WithSource(s.Name()).WithTags("securitytrails", "subdomain")
				if !add(a) {
					return out, nil
				}
			}
		} else if err == nil && (resp.StatusCode == 401 || resp.StatusCode == 403) {
			return nil, fmt.Errorf("securitytrails http %d (key bad)", resp.StatusCode)
		}
	}

	// 2) 当前 A 记录
	{
		resp, err := s.client.R().
			SetContext(ctx).
			SetHeaders(headers).
			Get(stBase + "/domain/" + domain)
		if err == nil && resp.StatusCode == 200 {
			for _, rec := range gjson.Parse(resp.String()).Get("current_dns.a.values").Array() {
				ip := rec.Get("ip").String()
				if ip == "" {
					continue
				}
				a := models.NewAsset().
					WithIP(ip).WithDomain(domain).WithHost(domain).
					WithSource(s.Name()).WithTags("securitytrails", "current-A")
				if !add(a) {
					return out, nil
				}
			}
		}
	}

	// 3) 历史 A 记录
	{
		resp, err := s.client.R().
			SetContext(ctx).
			SetHeaders(headers).
			Get(stBase + "/history/" + domain + "/dns/a")
		if err == nil && resp.StatusCode == 200 {
			for _, rec := range gjson.Parse(resp.String()).Get("records").Array() {
				first := rec.Get("first_seen").String()
				last := rec.Get("last_seen").String()
				for _, v := range rec.Get("values").Array() {
					ip := v.Get("ip").String()
					if ip == "" {
						continue
					}
					a := models.NewAsset().
						WithIP(ip).WithDomain(domain).WithHost(domain).
						WithSource(s.Name()).
						WithTags("securitytrails", "historical-A")
					if first != "" {
						a = a.WithTags("first:" + first)
					}
					if last != "" {
						a = a.WithTags("last:" + last)
					}
					if !add(a) {
						return out, nil
					}
				}
			}
		}
	}
	return out, nil
}
