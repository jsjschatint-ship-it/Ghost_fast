// Package zerozone_extra 零零信安 0.zone 扩展数据类型（被动）。
// 主引擎只查 site，本插件查询其他 9 种数据类型：
// domain, app, apk, email, code, org, member, branch, 。
package zerozone_extra

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

const apiURL = "https://0.zone/api/data/"

// 显示用的中文名（也用作 Asset.tags）
var typeLabels = map[string]string{
	"domain": "域名",
	"app":    "移动应用",
	"apk":    "APK",
	"email":  "邮箱",
	"code":   "代码泄露",
	"org":    "公司组织",
	"member": "公司成员",
	"branch": "分支机构",
	"supply": "供应链",

	"sensitive": "敏感信息",
}

// defaultTypes 默认查询类型（排除付费  和需精确公司名的 branch）
var defaultTypes = []string{"domain", "app", "apk", "email", "code", "org", "member"}

// ZeroZoneExtra 数据源
type ZeroZoneExtra struct {
	*source.BaseSource
	client *req.Client
	types  []string
}

// New 创建 ZeroZoneExtra 数据源
func New() *ZeroZoneExtra {
	return &ZeroZoneExtra{
		BaseSource: source.NewBaseSource("zerozone_extra"),
		client:     req.C().SetTimeout(25 * time.Second).SetUserAgent("Mozilla/5.0 (compatible; PassiveRecon/1.0)"),
		types:      defaultTypes,
	}
}

// Accepts 接受的输入类型
func (z *ZeroZoneExtra) Accepts() []string {
	return []string{"domain", "company", "ip", "keyword"}
}

// NeedsKey 是否需要 API Key
func (z *ZeroZoneExtra) NeedsKey() bool { return true }

// SetConfig 设置配置
func (z *ZeroZoneExtra) SetConfig(cfg map[string]any) error {
	_ = z.BaseSource.SetConfig(cfg)
	if v, ok := cfg["proxy"].(string); ok && v != "" {
		z.client.SetProxyURL(v)
	}
	if v, ok := cfg["timeout"].(int); ok && v > 0 {
		z.client.SetTimeout(time.Duration(v) * time.Second)
	}
	if v, ok := cfg["types"].([]string); ok && len(v) > 0 {
		z.types = v
	} else if v, ok := cfg["types"].([]any); ok {
		var ts []string
		for _, t := range v {
			if s, ok := t.(string); ok {
				ts = append(ts, s)
			}
		}
		if len(ts) > 0 {
			z.types = ts
		}
	}
	return nil
}

// Search 执行搜索
func (z *ZeroZoneExtra) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	cfg := &source.SearchConfig{MaxAssets: 100}
	for _, opt := range opts {
		opt(cfg)
	}
	if z.Key() == "" || target == "" {
		return nil, fmt.Errorf("zerozone_extra needs key and target")
	}
	maxPerType := cfg.MaxAssets
	if maxPerType <= 0 {
		maxPerType = 100
	}

	var all []*models.Asset
	for _, qt := range z.types {
		if _, ok := typeLabels[qt]; !ok {
			continue
		}
		assets, err := z.searchType(ctx, target, qt, maxPerType)
		if err != nil {
			continue
		}
		all = append(all, assets...)
	}
	return all, nil
}

// searchType 单一类型查询，自动分页
func (z *ZeroZoneExtra) searchType(ctx context.Context, query, qt string, maxTotal int) ([]*models.Asset, error) {
	const pagesize = 100
	var out []*models.Asset
	for page := 1; page <= 50; page++ {
		body := map[string]any{
			"query":       query,
			"query_type":  qt,
			"page":        page,
			"pagesize":    pagesize,
			"zone_key_id": z.Key(),
		}
		resp, err := z.client.R().
			SetContext(ctx).
			SetHeader("Content-Type", "application/json").
			SetBodyJsonMarshal(body).
			Post(apiURL)
		if err != nil {
			return out, err
		}
		if resp.StatusCode != 200 {
			return out, fmt.Errorf("0.zone status %d", resp.StatusCode)
		}
		raw := resp.String()
		code := gjson.Get(raw, "code").String()
		if code != "0" && code != "200" {
			return out, fmt.Errorf("0.zone code=%s msg=%s", code, gjson.Get(raw, "message").String())
		}
		items := gjson.Get(raw, "data").Array()
		if len(items) == 0 {
			items = gjson.Get(raw, "data.list").Array()
		}
		if len(items) == 0 {
			break
		}
		for _, it := range items {
			out = append(out, rowToAsset(it, qt))
			if len(out) >= maxTotal {
				return out, nil
			}
		}
		if len(items) < pagesize {
			break
		}
	}
	return out, nil
}

// rowToAsset 把单行 JSON 转 Asset
func rowToAsset(row gjson.Result, qt string) *models.Asset {
	label := typeLabels[qt]
	tags := []string{"0zone-" + qt, "0zone:" + label}

	company := flatStr(row.Get("company"))
	if company == "" {
		company = flatStr(row.Get("group"))
	}

	a := models.NewAsset().WithSource("zerozone-" + qt).WithTags(tags...)

	switch qt {
	case "domain":
		a.WithDomain(strOr(row, "domain", "root_domain")).
			WithHost(row.Get("domain").String()).
			WithIP(row.Get("msg.ip").String()).
			WithURL(row.Get("url").String()).
			WithICP(row.Get("icp").String()).
			WithOrg(company).
			WithUpdateTime(row.Get("timestamp").String())

	case "app", "apk":
		appURL := row.Get("msg.app_url").String()
		if appURL == "" {
			appURL = row.Get("msg.download_url").String()
		}
		a.WithTitle(truncate(row.Get("title").String(), 200)).
			WithURL(appURL).
			WithOrg(company).
			WithService(qt).
			WithICP(row.Get("icp").String()).
			WithUpdateTime(strOr(row, "timestamp_update", "timestamp"))
		if t := row.Get("type").String(); t != "" {
			a.WithTags(t)
		}

	case "email":
		em := flatStr(row.Get("email"))
		emType := flatStr(row.Get("email_type"))
		mailDomain := flatStr(row.Get("mail_domain"))
		leak := row.Get("leakage_num").Int()
		a.WithHost(em).
			WithDomain(mailDomain).
			WithOrg(company).
			WithTitle(strings.TrimRight(fmt.Sprintf("%s | 泄露 %d 次", emType, leak), " |")).
			WithUpdateTime(strOr(row, "leakage_update_time", "timestamp"))
		if leak > 0 {
			a.WithTags("有泄露")
		}

	case "code":
		repoStr := row.Get("repository.full_name").String()
		if repoStr == "" {
			repoStr = row.Get("repository.name").String()
		}
		if repoStr == "" {
			repoStr = flatStr(row.Get("repository"))
		}
		ownerStr := row.Get("owner.login").String()
		if ownerStr == "" {
			ownerStr = row.Get("owner.name").String()
		}
		if ownerStr == "" {
			ownerStr = flatStr(row.Get("owner"))
		}
		a.WithURL(row.Get("url").String()).
			WithTitle(truncate(row.Get("name").String(), 200)).
			WithHost(repoStr).
			WithOrg(ownerStr).
			WithUpdateTime(row.Get("timestamp").String())
		if src := row.Get("source").String(); src != "" {
			a.WithTags(src)
		}
		for _, t := range row.Get("tags").Array() {
			if s := t.String(); s != "" {
				a.WithTags(s)
			}
		}

	case "org":
		name := strOr(row, "company", "name_cn", "name_en")
		a.WithOrg(name).
			WithTitle(strOr(row, "name_cn", "name_en")).
			WithUpdateTime(strOr(row, "timestamp_update", "timestamp"))
		if p := row.Get("parent_company").String(); p != "" {
			a.WithTags(p)
		}
		for _, r := range row.Get("regions").Array() {
			if s := r.String(); s != "" {
				a.WithTags(s)
			}
		}

	case "member":
		positions := row.Get("msg.position").Array()
		var pos []string
		for _, p := range positions {
			pos = append(pos, p.String())
		}
		a.WithHost(row.Get("name").String()).
			WithOrg(company).
			WithTitle(strings.Join(pos, ", ")).
			WithUpdateTime(row.Get("timestamp").String())

	case "branch":
		a.WithOrg(strOr(row, "company", "name")).
			WithTitle(strOr(row, "address", "location")).
			WithUpdateTime(row.Get("timestamp").String())

	default:
		a.WithTitle(truncate(strOr(row, "title", "name"), 200)).
			WithURL(row.Get("url").String())
	}
	a.Normalize()
	return a
}

// flatStr 把任意值（含 list/dict）安全压成字符串
func flatStr(v gjson.Result) string {
	if !v.Exists() {
		return ""
	}
	switch {
	case v.IsArray():
		var parts []string
		for _, x := range v.Array() {
			if s := flatStr(x); s != "" {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, ",")
	case v.IsObject():
		for _, k := range []string{"name", "value", "title", "login", "full_name", "id"} {
			if g := v.Get(k); g.Exists() {
				return flatStr(g)
			}
		}
		return ""
	default:
		return v.String()
	}
}

// strOr 返回第一个非空字段
func strOr(row gjson.Result, keys ...string) string {
	for _, k := range keys {
		if s := row.Get(k).String(); s != "" {
			return s
		}
	}
	return ""
}

// truncate 截断字符串
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
