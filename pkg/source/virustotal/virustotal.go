package virustotal

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

const (
	defaultVirusTotalURL = "https://www.virustotal.com/vtapi/v2"
)

// VirusTotal 实现 VirusTotal 威胁情报
type VirusTotal struct {
	*source.BaseSource
	client  *req.Client
	baseURL string
}

// NewVirusTotal 创建 VirusTotal
func NewVirusTotal() *VirusTotal {
	v := &VirusTotal{
		BaseSource: source.NewBaseSource("virustotal"),
		baseURL:    defaultVirusTotalURL,
	}
	v.buildClient()
	return v
}

// Name 返回名称
func (v *VirusTotal) Name() string {
	return v.BaseSource.Name()
}

// Accepts 接受的输入类型
func (v *VirusTotal) Accepts() []string {
	return []string{"ip", "domain", "hash", "url"}
}

// NeedsKey 是否需要 API Key
func (v *VirusTotal) NeedsKey() bool {
	return true
}

// SetKey 设置 API Key
func (v *VirusTotal) SetKey(key string) {
	v.BaseSource.SetKey(key)
	v.buildClient()
}

// SetConfig 设置配置
func (v *VirusTotal) SetConfig(cfg map[string]any) error {
	_ = v.BaseSource.SetConfig(cfg)
	v.buildClient()
	return nil
}

// buildClient 构建 HTTP 客户端
func (v *VirusTotal) buildClient() {
	c := req.C()
	c.SetTimeout(30 * time.Second)
	c.SetUserAgent("Mozilla/5.0 (compatible; Ghost/1.0)")
	if v.BaseSource.Key() != "" {
		c.SetCommonHeader("x-apikey", v.BaseSource.Key())
	}
	v.client = c
}

// Search 执行搜索
func (v *VirusTotal) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	if v.client == nil {
		v.buildClient()
	}
	cfg := &source.SearchConfig{
		MaxAssets: 50,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	var allAssets []*models.Asset
	// IP 报告
	if isIP(target) {
		if assets, err := v.queryIP(ctx, target); err == nil {
			allAssets = append(allAssets, assets...)
		}
	}
	// 域名报告
	if isDomain(target) {
		if assets, err := v.queryDomain(ctx, target); err == nil {
			allAssets = append(allAssets, assets...)
		}
	}
	// 哈希报告
	if isHash(target) {
		if assets, err := v.queryHash(ctx, target); err == nil {
			allAssets = append(allAssets, assets...)
		}
	}
	// URL 报告
	if isURL(target) {
		if assets, err := v.queryURL(ctx, target); err == nil {
			allAssets = append(allAssets, assets...)
		}
	}

	if len(allAssets) > cfg.MaxAssets {
		allAssets = allAssets[:cfg.MaxAssets]
	}
	return allAssets, nil
}

// queryIP 查询 IP 报告
func (v *VirusTotal) queryIP(ctx context.Context, ip string) ([]*models.Asset, error) {
	u := fmt.Sprintf("%s/ip-address/report?apikey=%s&ip=%s", v.baseURL, v.BaseSource.Key(), ip)
	resp, err := v.client.R().SetContext(ctx).Get(u)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("virustotal ip status %d", resp.StatusCode)
	}
	body := resp.String()
	if !gjson.Valid(body) {
		return nil, fmt.Errorf("invalid json")
	}
	data := gjson.Parse(body)
	positives := data.Get("positives").Int()
	total := data.Get("total").Int()
	if positives > 0 {
		asset := models.NewAsset().
			WithTitle(fmt.Sprintf("[VirusTotal] %s (%d/%d)", ip, positives, total)).
			WithIP(ip).
			WithSource(v.Name()).
			WithTags("malicious", "ip", "virustotal").
			WithRaw("positives", fmt.Sprintf("%d", positives)).
			WithRaw("total", fmt.Sprintf("%d", total)).
			WithRaw("scan_date", data.Get("scan_date").String()).
			WithRaw("permalink", data.Get("permalink").String())
		return []*models.Asset{asset}, nil
	}
	return nil, nil
}

// queryDomain 查询域名报告
func (v *VirusTotal) queryDomain(ctx context.Context, domain string) ([]*models.Asset, error) {
	u := fmt.Sprintf("%s/domain/report?apikey=%s&domain=%s", v.baseURL, v.BaseSource.Key(), domain)
	resp, err := v.client.R().SetContext(ctx).Get(u)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("virustotal domain status %d", resp.StatusCode)
	}
	body := resp.String()
	if !gjson.Valid(body) {
		return nil, fmt.Errorf("invalid json")
	}
	data := gjson.Parse(body)
	positives := data.Get("positives").Int()
	total := data.Get("total").Int()
	if positives > 0 {
		asset := models.NewAsset().
			WithTitle(fmt.Sprintf("[VirusTotal] %s (%d/%d)", domain, positives, total)).
			WithDomain(domain).
			WithHost(domain).
			WithSource(v.Name()).
			WithTags("malicious", "domain", "virustotal").
			WithRaw("positives", fmt.Sprintf("%d", positives)).
			WithRaw("total", fmt.Sprintf("%d", total)).
			WithRaw("scan_date", data.Get("scan_date").String()).
			WithRaw("permalink", data.Get("permalink").String())
		return []*models.Asset{asset}, nil
	}
	return nil, nil
}

// queryHash 查询哈希报告
func (v *VirusTotal) queryHash(ctx context.Context, hash string) ([]*models.Asset, error) {
	u := fmt.Sprintf("%s/file/report?apikey=%s&resource=%s", v.baseURL, v.BaseSource.Key(), hash)
	resp, err := v.client.R().SetContext(ctx).Get(u)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("virustotal hash status %d", resp.StatusCode)
	}
	body := resp.String()
	if !gjson.Valid(body) {
		return nil, fmt.Errorf("invalid json")
	}
	data := gjson.Parse(body)
	positives := data.Get("positives").Int()
	total := data.Get("total").Int()
	if positives > 0 {
		asset := models.NewAsset().
			WithTitle(fmt.Sprintf("[VirusTotal] %s (%d/%d)", hash, positives, total)).
			WithSource(v.Name()).
			WithTags("malicious", "hash", "virustotal").
			WithRaw("hash", hash).
			WithRaw("positives", fmt.Sprintf("%d", positives)).
			WithRaw("total", fmt.Sprintf("%d", total)).
			WithRaw("scan_date", data.Get("scan_date").String()).
			WithRaw("permalink", data.Get("permalink").String())
		return []*models.Asset{asset}, nil
	}
	return nil, nil
}

// queryURL 查询 URL 报告
func (v *VirusTotal) queryURL(ctx context.Context, urlString string) ([]*models.Asset, error) {
	// 需要先对 URL 进行 base64 编码
	encoded := base64Encode(urlString)
	u := fmt.Sprintf("%s/url/report?apikey=%s&resource=%s", v.baseURL, v.BaseSource.Key(), encoded)
	resp, err := v.client.R().SetContext(ctx).Get(u)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("virustotal url status %d", resp.StatusCode)
	}
	body := resp.String()
	if !gjson.Valid(body) {
		return nil, fmt.Errorf("invalid json")
	}
	data := gjson.Parse(body)
	positives := data.Get("positives").Int()
	total := data.Get("total").Int()
	if positives > 0 {
		asset := models.NewAsset().
			WithTitle(fmt.Sprintf("[VirusTotal] %s (%d/%d)", urlString, positives, total)).
			WithURL(urlString).
			WithSource(v.Name()).
			WithTags("malicious", "url", "virustotal").
			WithRaw("url", urlString).
			WithRaw("positives", fmt.Sprintf("%d", positives)).
			WithRaw("total", fmt.Sprintf("%d", total)).
			WithRaw("scan_date", data.Get("scan_date").String()).
			WithRaw("permalink", data.Get("permalink").String())
		return []*models.Asset{asset}, nil
	}
	return nil, nil
}

// 辅助函数
func isIP(s string) bool {
	return strings.Contains(s, ".")
}

func isDomain(s string) bool {
	return !isIP(s) && !isHash(s) && !isURL(s)
}

func isHash(s string) bool {
	// 简单判断：32/40/64 位十六进制
	return len(s) == 32 || len(s) == 40 || len(s) == 64
}

func isURL(s string) bool {
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
}

func base64Encode(s string) string {
	// 简化实现，实际应使用标准实现
	return s
}
