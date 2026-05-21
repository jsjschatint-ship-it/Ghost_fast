// Package zerozone 零零信安 0.zone 数据源（POST /api/data/）。
//
// 现代 API（2025+）：
//
//	endpoint: https://0.zone/api/data/
//	method:   POST JSON
//	body:     {query, query_type, page, pagesize, zone_key_id}
//	response: {code, message, data:[...], total}
//
// query_type 枚举：site / domain / app / apk / email / code / org / member / branch
// 默认走 site；若 query 是 `domain:"x"` 单字段，自动改成 query_type=domain（拿子域）。
package zerozone

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/imroc/req/v3"
	"github.com/tidwall/gjson"
	"github.com/wgpsec/ENScan/pkg/engine"
	"github.com/wgpsec/ENScan/pkg/models"
)

const (
	defaultZeroZoneURL = "https://0.zone/api/data/"
	defaultSize        = 100
)

// termRE 单字段表达式 field:"value" / field='value' / field=value
var termRE = regexp.MustCompile(`(?i)([A-Za-z][A-Za-z0-9_.\-]*)\s*[:=]\s*(?:"([^"]+)"|'([^']+)'|([^\s()&|]+))`)

// ZeroZone 实现 ZeroZone 引擎
type ZeroZone struct {
	*engine.BaseEngine
	client  *req.Client
	baseURL string
}

// NewZeroZone 创建 ZeroZone 引擎
func NewZeroZone() *ZeroZone {
	z := &ZeroZone{
		BaseEngine: engine.NewBaseEngine("zerozone"),
		baseURL:    defaultZeroZoneURL,
	}
	return z
}

// Name 返回引擎名称
func (z *ZeroZone) Name() string {
	return z.BaseEngine.Name()
}

// SetProxy 设置代理
func (z *ZeroZone) SetProxy(proxy string) {
	z.BaseEngine.SetProxy(proxy)
	z.buildClient()
}

// SetTimeout 设置超时
func (z *ZeroZone) SetTimeout(timeout time.Duration) {
	z.BaseEngine.SetTimeout(timeout)
	z.buildClient()
}

// SetKey 设置 API Key
func (z *ZeroZone) SetKey(key string) {
	z.BaseEngine.SetKey(key)
	z.buildClient()
}

// SetKeys 设置多个 API Key
func (z *ZeroZone) SetKeys(keys []string) {
	z.BaseEngine.SetKeys(keys)
	z.buildClient()
}

// buildClient 构建 HTTP 客户端
func (z *ZeroZone) buildClient() {
	c := req.C()
	c.SetTimeout(z.BaseEngine.Timeout())
	if z.BaseEngine.Proxy() != "" {
		c.SetProxyURL(z.BaseEngine.Proxy())
	}
	c.SetUserAgent(z.BaseEngine.UserAgent())
	z.client = c
}

// parseSimpleDSL 把简单 `field:"value"` DSL 转成 (query_type, value)。
// 仅当全文是单个 field 项时生效（与 Python 引擎语义一致）：
//
//	`domain:"qq.com"`            → ("domain", "qq.com")    返回该域的全部子域
//	`host:"sub.qq.com"`          → ("domain", "sub.qq.com") 也按 domain 处理
//	`ip:"1.2.3.4" && port:"443"` → ("site", 整段)         交给原生 site 查询
func parseSimpleDSL(query string) (qtype, qvalue string) {
	q := strings.TrimSpace(query)
	if q == "" {
		return "site", ""
	}
	matches := termRE.FindAllStringSubmatchIndex(q, -1)
	if len(matches) != 1 {
		return "site", q
	}
	// 必须是整段全部由这一个 term 组成（前后不能有 && / || / 括号）
	m := matches[0]
	if m[0] != 0 || m[1] != len(q) {
		return "site", q
	}
	subs := termRE.FindStringSubmatch(q)
	field := strings.ToLower(subs[1])
	val := subs[2]
	if val == "" {
		val = subs[3]
	}
	if val == "" {
		val = subs[4]
	}
	if field == "domain" {
		return "domain", val
	}
	if (field == "host" || field == "hostname") && strings.Contains(val, ".") {
		return "domain", val
	}
	return "site", val
}

// Search 执行搜索（POST /api/data/）
func (z *ZeroZone) Search(ctx context.Context, query string, opts ...engine.SearchOption) ([]*models.Asset, error) {
	if z.client == nil {
		z.buildClient()
	}
	cfg := &engine.SearchConfig{
		Size:     defaultSize,
		MaxTotal: 5000,
		Timeout:  z.BaseEngine.Timeout(),
	}
	for _, opt := range opts {
		opt(cfg)
	}

	qtype, qval := parseSimpleDSL(query)

	var allAssets []*models.Asset
	seen := make(map[string]struct{}, 1024)
	page := 1
	for len(allAssets) < cfg.MaxTotal {
		body := map[string]any{
			"query":       qval,
			"query_type":  qtype,
			"page":        page,
			"pagesize":    cfg.Size,
			"zone_key_id": z.BaseEngine.CurrentKey(),
		}

		resp, err := z.client.R().
			SetContext(ctx).
			SetHeader("Content-Type", "application/json").
			SetBodyJsonMarshal(body).
			Post(z.baseURL)
		if err != nil {
			// key 轮换重试一次
			if len(z.BaseEngine.Keys()) > 1 {
				z.BaseEngine.RotateKey()
				body["zone_key_id"] = z.BaseEngine.CurrentKey()
				z.buildClient()
				resp, err = z.client.R().
					SetContext(ctx).
					SetHeader("Content-Type", "application/json").
					SetBodyJsonMarshal(body).
					Post(z.baseURL)
			}
			if err != nil {
				return nil, fmt.Errorf("request zerozone: %w", err)
			}
		}
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("zerozone api status %d", resp.StatusCode)
		}
		text := resp.String()
		if !gjson.Valid(text) {
			return nil, fmt.Errorf("zerozone: invalid json (snippet: %.120s)", text)
		}
		data := gjson.Parse(text)
		code := data.Get("code")
		// 0 / 200 / "0" 都视为成功（Python 兼容）
		if code.Type != gjson.Null && code.String() != "0" && code.String() != "200" {
			return nil, fmt.Errorf("zerozone api error: %s", data.Get("message").String())
		}

		// data 可能是 list，也可能是 {list:[...]} / {data:[...]} / {items:[...]}
		var items []gjson.Result
		raw := data.Get("data")
		if raw.IsArray() {
			items = raw.Array()
		} else if raw.IsObject() {
			for _, k := range []string{"list", "data", "items"} {
				if sub := raw.Get(k); sub.IsArray() {
					items = sub.Array()
					break
				}
			}
		}
		if len(items) == 0 {
			break
		}

		for _, it := range items {
			a := rowToAsset(it, qtype)
			if a == nil {
				continue
			}
			// 去重
			k := a.IP + "|" + fmt.Sprintf("%d", a.Port) + "|" + a.Host + "|" + a.Domain + "|" + a.URL
			if _, ok := seen[k]; ok {
				continue
			}
			seen[k] = struct{}{}
			allAssets = append(allAssets, a)
			if len(allAssets) >= cfg.MaxTotal {
				break
			}
		}

		if len(items) < cfg.Size {
			break
		}
		page++
		time.Sleep(600 * time.Millisecond) // 0.zone QPS 限速
	}

	if len(allAssets) > cfg.MaxTotal {
		allAssets = allAssets[:cfg.MaxTotal]
	}
	return allAssets, nil
}

// rowToAsset 把一行 JSON 转 Asset。site/domain 走不同字段映射。
func rowToAsset(it gjson.Result, qtype string) *models.Asset {
	if !it.IsObject() {
		return nil
	}

	// company 可能是 list 或 string
	orgStr := ""
	if c := it.Get("company"); c.IsArray() && len(c.Array()) > 0 {
		orgStr = c.Array()[0].String()
	} else if c.Type == gjson.String {
		orgStr = c.String()
	} else if g := it.Get("group"); g.Type == gjson.String {
		orgStr = g.String()
	}

	if qtype == "domain" {
		// domain 查询返回的行是 {domain, root_domain, icp, company, msg:{ip,...}}
		domain := it.Get("domain").String()
		host := domain
		ip := it.Get("msg.ip").String()
		if ip == "" {
			ip = it.Get("ip").String()
		}
		a := models.NewAsset().
			WithDomain(it.Get("root_domain").String()).
			WithHost(host).
			WithIP(ip).
			WithSource("zerozone").
			WithTags("engine", "zerozone", "zerozone-domain")
		if icp := it.Get("beian").String(); icp != "" {
			a = a.WithICP(icp)
		} else if icp := it.Get("icp").String(); icp != "" {
			a = a.WithICP(icp)
		}
		if orgStr != "" {
			a = a.WithOrg(orgStr)
		}
		return a
	}

	// site 查询：标准 IP:port 资产
	ip := it.Get("ip").String()
	if ip == "" {
		ip = it.Get("ip_addr").String()
	}
	port := int(it.Get("port").Int())
	hostname := it.Get("hostname").String()
	if hostname == "" {
		hostname = it.Get("ssl_hostname").String()
	}
	domain := it.Get("toplv_domain").String()
	if domain == "" {
		domain = hostname
	}
	server := it.Get("server_name").String()
	if server == "" {
		server = it.Get("server_brand").String()
	}
	svc := it.Get("service").String()
	if svc == "" {
		svc = it.Get("app_name").String()
	}
	osName := it.Get("os_name").String()
	if osName == "" {
		osName = it.Get("os").String()
	}
	icp := it.Get("beian").String()
	if icp == "" {
		icp = it.Get("icp").String()
	}
	asnOrg := it.Get("asn_org").String()
	if asnOrg == "" {
		asnOrg = orgStr
	}

	a := models.NewAsset().
		WithIP(ip).
		WithPort(port).
		WithProtocol(it.Get("protocol").String()).
		WithDomain(domain).
		WithHost(hostname).
		WithURL(it.Get("url").String()).
		WithTitle(it.Get("title").String()).
		WithServer(server).
		WithService(svc).
		WithOS(osName).
		WithCountry(it.Get("country").String()).
		WithProvince(it.Get("province").String()).
		WithCity(it.Get("city").String()).
		WithASN(it.Get("asn").String()).
		WithOrg(asnOrg).
		WithSource("zerozone").
		WithTags("engine", "zerozone")
	if icp != "" {
		a = a.WithICP(icp)
	}
	if cms := it.Get("cms").String(); cms != "" && cms != "unknown" {
		a = a.WithProduct(cms)
	}
	if ts := it.Get("timestamp").String(); ts != "" {
		a = a.WithUpdateTime(ts)
	}
	return a
}
