package dnsdumpster

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/imroc/req/v3"
	"github.com/tidwall/gjson"
	"github.com/wgpsec/ENScan/pkg/models"
	"github.com/wgpsec/ENScan/pkg/source"
)

// DNSDumpster 实现 DNS Dumpster 域名枚举
type DNSDumpster struct {
	*source.BaseSource
	client *req.Client
}

// NewDNSDumpster 创建 DNSDumpster
func NewDNSDumpster() *DNSDumpster {
	d := &DNSDumpster{
		BaseSource: source.NewBaseSource("dnsdumpster"),
	}
	d.buildClient()
	return d
}

// Name 返回名称
func (d *DNSDumpster) Name() string {
	return d.BaseSource.Name()
}

// Accepts 接受的输入类型
func (d *DNSDumpster) Accepts() []string {
	return []string{"domain"}
}

// NeedsKey 是否需要 API Key
func (d *DNSDumpster) NeedsKey() bool {
	return true
}

// SetKey 设置 API Key
func (d *DNSDumpster) SetKey(key string) {
	d.BaseSource.SetKey(key)
	d.buildClient()
}

// SetConfig 设置配置
func (d *DNSDumpster) SetConfig(cfg map[string]any) error {
	_ = d.BaseSource.SetConfig(cfg)
	d.buildClient()
	return nil
}

// buildClient 构建 HTTP 客户端
func (d *DNSDumpster) buildClient() {
	c := req.C()
	c.SetTimeout(30 * time.Second)
	c.SetUserAgent("Mozilla/5.0 (compatible; Ghost/1.0)")
	if d.BaseSource.Key() != "" {
		c.SetCommonHeader("X-API-Key", d.BaseSource.Key())
	}
	d.client = c
}

// Search 执行搜索
func (d *DNSDumpster) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	cfg := &source.SearchConfig{
		MaxAssets: 100,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	if d.BaseSource.Key() == "" {
		return nil, fmt.Errorf("dnsdumpster needs api key")
	}
	// 新版公开 API：https://api.dnsdumpster.com/domain/{domain}
	// 閴存潈澶?X-API-Key 宸插湪 buildClient 璁剧疆
	u := fmt.Sprintf("https://api.dnsdumpster.com/domain/%s", url.PathEscape(target))
	resp, err := d.client.R().SetContext(ctx).Get(u)
	if err != nil {
		return nil, fmt.Errorf("request dnsdumpster: %w", err)
	}
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return nil, fmt.Errorf("dnsdumpster api unauthorized: %d", resp.StatusCode)
	}
	if resp.StatusCode == 404 {
		return nil, nil
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("dnsdumpster api status %d", resp.StatusCode)
	}
	body := resp.String()
	if !gjson.Valid(body) {
		return nil, fmt.Errorf("invalid json")
	}
	data := gjson.Parse(body)
	var allAssets []*models.Asset
	// a / ns / mx / cname 记录
	for _, k := range []string{"a", "ns", "mx", "cname", "txt"} {
		for _, item := range data.Get(k).Array() {
			host := item.Get("host").String()
			if host == "" {
				host = item.Get("ips.0.ip").String()
			}
			ip := item.Get("ips.0.ip").String()
			if host == "" && ip == "" {
				continue
			}
			asset := models.NewAsset().
				WithTitle(fmt.Sprintf("[DNSDumpster] %s %s", k, host)).
				WithHost(host).WithDomain(target).WithIP(ip).
				WithSource(d.Name()).
				WithTags("dnsdumpster", "dns:"+k).
				WithRaw("record", k).
				WithRaw("ip", ip)
			allAssets = append(allAssets, asset)
		}
	}

	if len(allAssets) > cfg.MaxAssets {
		allAssets = allAssets[:cfg.MaxAssets]
	}
	return allAssets, nil
}
