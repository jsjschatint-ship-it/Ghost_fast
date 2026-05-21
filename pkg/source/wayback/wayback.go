// Package wayback Wayback Machine (web.archive.org) CDX API 被动数据源。
// 完全被动，不向目标资产发任何流量。
package wayback

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/imroc/req/v3"
	"github.com/tidwall/gjson"
	"github.com/wgpsec/ENScan/pkg/core"
	"github.com/wgpsec/ENScan/pkg/models"
	"github.com/wgpsec/ENScan/pkg/source"
)

const cdxURL = "https://web.archive.org/cdx/search/cdx"

// Wayback 数据源
type Wayback struct {
	*source.BaseSource
	client *req.Client
}

// New 创建 Wayback 数据源
func New() *Wayback {
	return &Wayback{
		BaseSource: source.NewBaseSource("wayback"),
		client:     req.C().SetTimeout(60 * time.Second).SetUserAgent("Mozilla/5.0 (compatible; PassiveRecon/1.0)"),
	}
}

// Accepts 接受的输入类型
func (w *Wayback) Accepts() []string { return []string{"domain"} }

// NeedsKey 是否需要 API Key
func (w *Wayback) NeedsKey() bool { return false }

// SetConfig 设置配置
func (w *Wayback) SetConfig(cfg map[string]any) error {
	_ = w.BaseSource.SetConfig(cfg)
	if v, ok := cfg["proxy"].(string); ok && v != "" {
		w.client.SetProxyURL(v)
	}
	if v, ok := cfg["timeout"].(int); ok && v > 0 {
		w.client.SetTimeout(time.Duration(v) * time.Second)
	}
	return nil
}

// Search 执行搜索
func (w *Wayback) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	cfg := &source.SearchConfig{MaxAssets: 5000}
	for _, opt := range opts {
		opt(cfg)
	}
	domain := strings.TrimSpace(target)
	if domain == "" {
		return nil, nil
	}
	limit := cfg.MaxAssets
	if limit <= 0 {
		limit = 5000
	}

	u, _ := url.Parse(cdxURL)
	q := u.Query()
	q.Set("url", domain)
	q.Set("output", "json")
	q.Set("fl", "original,timestamp,mimetype,statuscode,digest")
	q.Set("collapse", "urlkey")
	q.Set("matchType", "domain")
	q.Set("limit", strconv.Itoa(limit))
	u.RawQuery = q.Encode()

	resp, err := w.client.R().
		SetContext(ctx).
		SetHeader("Accept", "application/json,text/plain,*/*").
		Get(u.String())
	if err != nil {
		return nil, fmt.Errorf("wayback request: %w", err)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("wayback status %d", resp.StatusCode)
	}

	body := resp.String()
	if !strings.HasPrefix(strings.TrimSpace(body), "[") {
		return nil, nil
	}
	rows := gjson.Parse(body).Array()
	if len(rows) < 2 {
		return nil, nil
	}

	// 第一行是 header
	headers := rows[0].Array()
	idx := map[string]int{}
	for i, h := range headers {
		idx[h.String()] = i
	}
	getF := func(row []gjson.Result, key string) string {
		if i, ok := idx[key]; ok && i < len(row) {
			return row[i].String()
		}
		return ""
	}

	out := make([]*models.Asset, 0, len(rows)-1)
	seenSubs := map[string]bool{}
	rootDomain := strings.TrimPrefix(strings.ToLower(domain), "*.")

	for _, r := range rows[1:] {
		row := r.Array()
		urlStr := getF(row, "original")
		if urlStr == "" {
			continue
		}
		ts := getF(row, "timestamp")
		mime := getF(row, "mimetype")
		sc := getF(row, "statuscode")
		host := parseHost(urlStr)
		if host == "" {
			continue
		}

		title := ""
		if sc != "" || mime != "" {
			title = fmt.Sprintf("[%s] %s", sc, mime)
		}
		a := models.NewAsset().
			WithDomain(host).WithHost(host).WithURL(urlStr).
			WithTitle(title).
			WithUpdateTime(fmtTS(ts)).
			WithSource("wayback")
		// 高价值路径分类
		if tags := core.Classify(urlStr); len(tags) > 0 {
			a.WithTags(tags...)
		}
		a.WithRaw("timestamp", ts)
		a.WithRaw("mimetype", mime)
		a.WithRaw("statuscode", sc)
		a.WithRaw("snapshot", "https://web.archive.org/web/"+ts+"/"+urlStr)
		a.Normalize()
		out = append(out, a)

		// 子域单独成条
		if !seenSubs[host] && strings.HasSuffix(host, rootDomain) {
			seenSubs[host] = true
			sub := models.NewAsset().
				WithDomain(host).WithHost(host).
				WithSource("wayback").
				WithUpdateTime(fmtTS(ts))
			sub.WithRaw("first_seen_ts", ts)
			sub.Normalize()
			out = append(out, sub)
		}
	}
	return out, nil
}

// parseHost 从 URL 抽 host
func parseHost(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// fmtTS 把 yyyymmddhhmmss 格式化为可读字符串
func fmtTS(ts string) string {
	if len(ts) < 8 {
		return ts
	}
	get := func(s, e int) string {
		if e > len(ts) {
			return "00"
		}
		return ts[s:e]
	}
	return fmt.Sprintf("%s-%s-%s %s:%s:%s",
		get(0, 4), get(4, 6), get(6, 8),
		get(8, 10), get(10, 12), get(12, 14))
}
