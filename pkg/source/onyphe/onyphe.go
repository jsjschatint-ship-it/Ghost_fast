package onyphe

// Onyphe - 海外测绘 / 暴露面，免费 1000/月。
// 两步：
//   1) GET /api/v2/summary/domain/<domain>
//   2) GET /api/v2/search/datascan?q=domain:<domain>&page=1..3&size=100
// Auth: "Authorization: bearer <key>"

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

const onypheBase = "https://www.onyphe.io/api/v2"

type Onyphe struct {
	*source.BaseSource
	client *req.Client
}

func NewOnyphe() *Onyphe {
	return &Onyphe{
		BaseSource: source.NewBaseSource("onyphe"),
		client:     req.C().SetTimeout(30 * time.Second).SetUserAgent("Ghost/1.0"),
	}
}

func (s *Onyphe) Name() string      { return s.BaseSource.Name() }
func (s *Onyphe) Accepts() []string { return []string{"domain", "ip"} }
func (s *Onyphe) NeedsKey() bool    { return true }

func (s *Onyphe) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	cfg := &source.SearchConfig{MaxAssets: 500}
	for _, opt := range opts {
		opt(cfg)
	}
	if target == "" || !strings.Contains(target, ".") {
		return nil, nil
	}
	key := s.BaseSource.Key()
	if key == "" {
		return nil, fmt.Errorf("onyphe needs api key")
	}
	domain := strings.ToLower(strings.TrimSpace(target))
	auth := "bearer " + key

	out := make([]*models.Asset, 0, 128)
	seen := make(map[string]struct{}, 256)
	add := func(a *models.Asset) bool {
		k := fmt.Sprintf("%s|%d|%s|%s", a.IP, a.Port, a.Host, a.Domain)
		if _, ok := seen[k]; ok {
			return false
		}
		seen[k] = struct{}{}
		out = append(out, a)
		return cfg.MaxAssets <= 0 || len(out) < cfg.MaxAssets
	}

	// 1) summary
	{
		resp, err := s.client.R().
			SetContext(ctx).
			SetHeader("Authorization", auth).
			SetHeader("Accept", "application/json").
			Get(onypheBase + "/summary/domain/" + domain)
		if err == nil && resp.StatusCode == 200 {
			for _, it := range gjson.Parse(resp.String()).Get("results").Array() {
				if !add(onypheRowToAsset(it, s.Name())) {
					return out, nil
				}
			}
		}
	}

	// 2) datascan paged
	for page := 1; page <= 3; page++ {
		resp, err := s.client.R().
			SetContext(ctx).
			SetHeader("Authorization", auth).
			SetHeader("Accept", "application/json").
			SetQueryParams(map[string]string{
				"q":    "domain:" + domain,
				"page": fmt.Sprintf("%d", page),
				"size": "100",
			}).
			Get(onypheBase + "/search/datascan")
		if err != nil {
			break
		}
		if resp.StatusCode != 200 {
			if page == 1 && (resp.StatusCode == 401 || resp.StatusCode == 403) {
				return nil, fmt.Errorf("onyphe http %d (key bad)", resp.StatusCode)
			}
			break
		}
		results := gjson.Parse(resp.String()).Get("results").Array()
		if len(results) == 0 {
			break
		}
		newCount := 0
		for _, it := range results {
			a := onypheRowToAsset(it, s.Name())
			if !add(a) {
				return out, nil
			}
			newCount++
		}
		if newCount == 0 {
			break
		}
	}
	return out, nil
}

func onypheRowToAsset(it gjson.Result, srcName string) *models.Asset {
	ip := it.Get("ip").String()
	port := int(it.Get("port").Int())
	// hostname 可能是 array 或 string
	host := ""
	if hn := it.Get("hostname"); hn.Exists() {
		if hn.IsArray() {
			arr := hn.Array()
			if len(arr) > 0 {
				host = strings.ToLower(arr[0].String())
			}
		} else {
			host = strings.ToLower(hn.String())
		}
	}
	if host == "" {
		host = strings.ToLower(it.Get("domain").String())
	}
	proto := strings.ToLower(it.Get("protocol").String())
	if proto == "" {
		proto = strings.ToLower(it.Get("scheme").String())
	}
	server := it.Get("headers.server").String()
	if server == "" {
		server = it.Get("header.server").String()
	}
	if server == "" {
		server = it.Get("headers.Server").String()
	}
	org := it.Get("organization").String()
	if org == "" {
		org = it.Get("subnet").String()
	}
	domain := ""
	if strings.Contains(host, ".") {
		domain = host
	}
	a := models.NewAsset().
		WithIP(ip).
		WithPort(port).
		WithProtocol(proto).
		WithDomain(domain).
		WithHost(host).
		WithTitle(it.Get("title").String()).
		WithServer(server).
		WithCountry(it.Get("country").String()).
		WithCity(it.Get("city").String()).
		WithASN(it.Get("asn").String()).
		WithOrg(org).
		WithSource(srcName).
		WithTags("onyphe")
	if cat := it.Get("category").String(); cat != "" {
		a = a.WithRaw("category", cat)
	}
	return a
}
