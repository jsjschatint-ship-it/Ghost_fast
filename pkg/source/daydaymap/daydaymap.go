package daydaymap

// DayDayMap (daydaymap.com) - 国内新兴空间测绘平台，需 api-key（每月有免费配额）。
// POST https://www.daydaymap.com/api/v1/raymap/search/all
// 需要先对 URL 进行 base64 编码
// header: api-key: <key>
// 默认按 domain="<target>" 查询，可用 raw_query=... 覆盖。
// 翻页：100/页，最多 5 页（500 条上限）。
import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/imroc/req/v3"
	"github.com/tidwall/gjson"
	"github.com/wgpsec/ENScan/pkg/models"
	"github.com/wgpsec/ENScan/pkg/source"
)

const ddmURL = "https://www.daydaymap.com/api/v1/raymap/search/all"

type DayDayMap struct {
	*source.BaseSource
	client *req.Client
}

func NewDayDayMap() *DayDayMap {
	return &DayDayMap{
		BaseSource: source.NewBaseSource("daydaymap"),
		client:     req.C().SetTimeout(30 * time.Second).SetUserAgent("Ghost/1.0"),
	}
}

func (s *DayDayMap) Name() string      { return s.BaseSource.Name() }
func (s *DayDayMap) Accepts() []string { return []string{"domain", "ip"} }
func (s *DayDayMap) NeedsKey() bool    { return true }

func (s *DayDayMap) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	cfg := &source.SearchConfig{MaxAssets: 500}
	for _, opt := range opts {
		opt(cfg)
	}
	if target == "" {
		return nil, nil
	}
	key := s.BaseSource.Key()
	if key == "" {
		return nil, fmt.Errorf("daydaymap needs api key")
	}

	q := ""
	if c := s.BaseSource.Config(); c != nil {
		if v, ok := c["raw_query"].(string); ok {
			q = v
		}
	}
	if q == "" {
		q = fmt.Sprintf(`domain="%s"`, strings.ToLower(strings.TrimSpace(target)))
	}

	headers := map[string]string{
		"api-key":      key,
		"Content-Type": "application/json",
		"Accept":       "application/json",
	}

	out := make([]*models.Asset, 0, 100)
	seen := make(map[string]struct{}, 256)

	for page := 1; page <= 5; page++ {
		payload := map[string]any{
			"keyword":   base64.StdEncoding.EncodeToString([]byte(q)),
			"page":      page,
			"page_size": 100,
		}
		resp, err := s.client.R().
			SetContext(ctx).
			SetHeaders(headers).
			SetBodyJsonMarshal(payload).
			Post(ddmURL)
		if err != nil {
			if page == 1 {
				return nil, fmt.Errorf("daydaymap: %w", err)
			}
			break
		}
		if resp.StatusCode != 200 {
			if page == 1 {
				return nil, fmt.Errorf("daydaymap http %d", resp.StatusCode)
			}
			break
		}
		body := resp.String()
		if !gjson.Valid(body) {
			break
		}
		data := gjson.Parse(body)
		code := data.Get("code").String()
		if !(code == "200" || code == "0") {
			if page == 1 {
				return nil, fmt.Errorf("daydaymap code=%s msg=%s", code, data.Get("msg").String())
			}
			break
		}
		items := data.Get("data.list").Array()
		if len(items) == 0 {
			break
		}
		newCount := 0
		for _, it := range items {
			ip := it.Get("ip").String()
			port := int(it.Get("port").Int())
			host := strings.ToLower(it.Get("host").String())
			if host == "" {
				host = strings.ToLower(it.Get("domain").String())
			}
			k := fmt.Sprintf("%s|%d|%s", ip, port, host)
			if _, ok := seen[k]; ok {
				continue
			}
			seen[k] = struct{}{}
			newCount++

			domain := it.Get("domain").String()
			if domain == "" && strings.Contains(host, ".") {
				domain = host
			}
			url := it.Get("url").String()
			if url == "" {
				url = it.Get("link").String()
			}
			server := it.Get("server").String()
			if server == "" {
				server = it.Get("header_hash").String()
			}
			province := it.Get("region").String()
			if province == "" {
				province = it.Get("province").String()
			}
			org := it.Get("isp").String()
			if org == "" {
				org = it.Get("organization").String()
			}
			updateTime := it.Get("update_time").String()
			if updateTime == "" {
				updateTime = it.Get("timestamp").String()
			}

			a := models.NewAsset().
				WithIP(ip).
				WithPort(port).
				WithProtocol(strings.ToLower(it.Get("protocol").String())).
				WithDomain(domain).
				WithHost(host).
				WithURL(url).
				WithTitle(it.Get("title").String()).
				WithServer(server).
				WithCountry(it.Get("country").String()).
				WithProvince(province).
				WithCity(it.Get("city").String()).
				WithASN(it.Get("asn").String()).
				WithOrg(org).
				WithICP(it.Get("icp").String()).
				WithUpdateTime(updateTime).
				WithSource(s.Name()).
				WithTags("daydaymap")
			out = append(out, a)
			if cfg.MaxAssets > 0 && len(out) >= cfg.MaxAssets {
				return out, nil
			}
		}
		if newCount < 100 {
			break
		}
	}
	return out, nil
}
