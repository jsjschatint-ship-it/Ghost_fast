package bdziyi

// bdziyi 的 ZoomEye 代理：POST /hygj/zeyq/search.php，body form-urlencoded：
//   query=<DSL>&page=N&pagesize=N&sub_type=v4|v6|web
// 返回原生 ZoomEye JSON：{code, total, data:[{ip,port,domain,title,...}]}
// 单页上限 500；翻页间隔默认 1500ms。

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/tidwall/gjson"
	"github.com/wgpsec/ENScan/pkg/models"
	"github.com/wgpsec/ENScan/pkg/source"
)

const bdZEURL = "https://bdziyi.com/hygj/zeyq/search.php"

func (s *BDZiyi) searchZE(ctx context.Context, target string, cfg *source.SearchConfig) ([]*models.Asset, error) {
	cookie := s.cookie()
	if cookie == "" {
		return nil, nil // 未配 cookie 静默跳过
	}

	q := s.configString("raw_query", "")
	if q == "" {
		q = fmt.Sprintf(`domain="%s"`, strings.ToLower(strings.TrimSpace(target)))
	}
	subType := s.configString("sub_type", "v4")
	maxPages := s.configInt("max_pages", 3)
	pageSize := s.configInt("page_size", 100)
	if pageSize < 1 {
		pageSize = 1
	}
	if pageSize > 500 {
		pageSize = 500
	}
	sleepMs := s.configInt("sleep_ms", 1500)

	headers := s.baseHeaders(bdHomeZE, "application/x-www-form-urlencoded")
	headers["Cookie"] = cookie

	var out []*models.Asset
	for page := 1; page <= maxPages; page++ {
		form := url.Values{}
		form.Set("query", q)
		form.Set("page", fmt.Sprintf("%d", page))
		form.Set("pagesize", fmt.Sprintf("%d", pageSize))
		form.Set("sub_type", subType)

		resp, err := s.client.R().
			SetContext(ctx).
			SetHeaders(headers).
			SetBodyString(form.Encode()).
			Post(bdZEURL)
		if err != nil {
			if page == 1 {
				return []*models.Asset{s.errAsset("异常 %v", err)}, nil
			}
			break
		}
		if resp.StatusCode != 200 {
			if page == 1 {
				return []*models.Asset{
					s.errAsset("HTTP %d（cookie 失效或对方故障）", resp.StatusCode),
				}, nil
			}
			break
		}
		txt := resp.String()
		if !gjson.Valid(txt) {
			if page == 1 {
				return []*models.Asset{s.errAsset("bad json")}, nil
			}
			break
		}
		data := gjson.Parse(txt)
		code := data.Get("code").String()
		// 兼容 60000 / 200 / 0（数字或字符串）
		if !(code == "60000" || code == "200" || code == "0" || code == "") {
			if page == 1 {
				return []*models.Asset{
					s.errAsset("code=%s msg=%s", code, data.Get("message").String()),
				}, nil
			}
			break
		}
		items := data.Get("data").Array()
		if len(items) == 0 {
			items = data.Get("results").Array()
		}
		if len(items) == 0 {
			break
		}
		for _, it := range items {
			a := zeItemToAsset(it, s.Name())
			if a == nil {
				continue
			}
			out = append(out, a)
			if cfg.MaxAssets > 0 && len(out) >= cfg.MaxAssets {
				return out, nil
			}
		}
		if len(items) < pageSize {
			break
		}
		if page < maxPages {
			time.Sleep(time.Duration(sleepMs) * time.Millisecond)
		}
	}
	return out, nil
}

func zeItemToAsset(it gjson.Result, srcName string) *models.Asset {
	if !it.IsObject() {
		return nil
	}
	title := it.Get("title")
	titleStr := ""
	if title.IsArray() {
		parts := []string{}
		for _, t := range title.Array() {
			if v := strings.TrimSpace(t.String()); v != "" {
				parts = append(parts, v)
			}
		}
		titleStr = strings.Join(parts, " ")
	} else {
		titleStr = title.String()
	}
	port := int(it.Get("port").Int())
	asnRaw := strings.TrimSpace(it.Get("asn").String())
	asn := ""
	if asnRaw != "" && asnRaw != "0" {
		asn = "AS" + asnRaw
	}
	isp := it.Get("isp.name").String()
	if isp == "" {
		isp = it.Get("organization.name").String()
	}
	country := it.Get("country.name").String()
	if country == "" {
		country = it.Get("country").String()
	}
	province := it.Get("province.name").String()
	if province == "" {
		province = it.Get("province").String()
	}
	city := it.Get("city.name").String()
	if city == "" {
		city = it.Get("city").String()
	}
	server := it.Get("header.server.name").String()
	if server == "" {
		server = it.Get("server").String()
	}
	proto := strings.ToLower(it.Get("service").String())
	if proto == "" {
		proto = strings.ToLower(it.Get("protocol").String())
	}
	host := strings.ToLower(it.Get("domain").String())
	if host == "" {
		host = strings.ToLower(it.Get("hostname").String())
	}
	domain := strings.ToLower(it.Get("domain").String())

	a := models.NewAsset().
		WithIP(it.Get("ip").String()).
		WithPort(port).
		WithHost(host).
		WithDomain(domain).
		WithURL(it.Get("url").String()).
		WithTitle(titleStr).
		WithProtocol(proto).
		WithServer(server).
		WithCountry(country).
		WithProvince(province).
		WithCity(city).
		WithASN(asn).
		WithOrg(isp).
		WithUpdateTime(it.Get("update_time").String()).
		WithSource(srcName).
		WithTags("bdziyi", "ze-proxy")
	if it.Get("honeypot").Exists() && it.Get("honeypot").Bool() {
		a = a.WithTags("honeypot")
	}
	if it.Get("idc").Exists() && it.Get("idc").Bool() {
		a = a.WithTags("idc")
	}
	if v := it.Get("iconhash_md5").String(); v != "" {
		a = a.WithFaviconHash(v)
	}
	if p := it.Get("product").String(); p != "" {
		a = a.WithProduct(p)
	}
	return a
}
