package bdziyi

// bdziyi 的 FOFA 代理：POST /hygj/ssyqapi*.php，body form-urlencoded：
//   action=fofa_cx&fofa_yf=<DSL>&fofa_ts=<size>
// FOFA DSL 内的 `&` 需要先转成 `%26` 防止 form 解析把 fofa_yf 拆掉。
// 返回 JSON：
//   {error, consumed_fpoint, required_fpoints, size, page, results}
// results 是二维数组：[[url, ip, title, port, ?, protocol], ...]

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

var bdFOFAEndpoints = []string{
	"https://bdziyi.com/hygj/ssyqapi.php",
	"https://bdziyi.com/hygj/ssyqapijk2.php",
	"https://bdziyi.com/hygj/ssyqapijk3.php",
}

func (s *BDZiyi) searchFOFA(ctx context.Context, target string, cfg *source.SearchConfig) ([]*models.Asset, error) {
	cookie := s.cookie()
	if cookie == "" {
		// 静默跳过：未配 cookie 不算错误，避免夸大错误计数。配了才跑。
		return nil, nil
	}

	// 选 DSL：优先 raw_query，否则按根域查
	q := s.configString("raw_query", "")
	if q == "" {
		q = fmt.Sprintf(`domain="%s"`, strings.ToLower(strings.TrimSpace(target)))
	}
	// `&` → `%26`（FOFA && 才能挺过 form 解析）
	qEncoded := strings.ReplaceAll(q, "&", "%26")

	size := s.configInt("size", 100)
	if cfg.MaxAssets > 0 && size > cfg.MaxAssets {
		size = cfg.MaxAssets
	}
	sleepMs := s.configInt("sleep_ms", 5500) // 站点限速 5s/次

	body := "action=fofa_cx" +
		"&fofa_yf=" + url.QueryEscape(qEncoded) +
		"&fofa_ts=" + fmt.Sprintf("%d", size)

	headers := s.baseHeaders(bdHomeFOFA, "application/x-www-form-urlencoded")
	headers["X-Requested-With"] = "XMLHttpRequest"
	headers["Cookie"] = cookie

	var lastErr string
	for i, ep := range bdFOFAEndpoints {
		resp, err := s.client.R().
			SetContext(ctx).
			SetHeaders(headers).
			SetBodyString(body).
			Post(ep)
		if err != nil {
			lastErr = err.Error()
			continue
		}
		if resp.StatusCode != 200 {
			lastErr = fmt.Sprintf("HTTP %d", resp.StatusCode)
			// 限速/服务过载，缓一下再试下一个
			if (resp.StatusCode == 429 || resp.StatusCode == 503) && i+1 < len(bdFOFAEndpoints) {
				time.Sleep(time.Duration(sleepMs) * time.Millisecond)
			}
			continue
		}
		txt := resp.String()
		if !gjson.Valid(txt) {
			lastErr = "bad json"
			continue
		}
		data := gjson.Parse(txt)
		if data.Get("error").Bool() {
			lastErr = fmt.Sprintf("error=%v tip=%s",
				data.Get("error").Value(), data.Get("tip").String())
			continue
		}
		rows := data.Get("results").Array()
		assets := make([]*models.Asset, 0, len(rows))
		for _, row := range rows {
			a := fofaRowToAsset(row, s.Name())
			if a == nil {
				continue
			}
			assets = append(assets, a)
			if cfg.MaxAssets > 0 && len(assets) >= cfg.MaxAssets {
				break
			}
		}
		return assets, nil
	}
	// 全部端点失败
	return []*models.Asset{s.errAsset("所有端点失败: %s", lastErr)}, nil
}

// fofaRowToAsset 把 [url, ip, title, port, ?, protocol] 转换为 Asset
func fofaRowToAsset(row gjson.Result, srcName string) *models.Asset {
	if !row.IsArray() {
		return nil
	}
	arr := row.Array()
	if len(arr) < 2 {
		return nil
	}
	get := func(i int) string {
		if i >= len(arr) {
			return ""
		}
		return strings.TrimSpace(arr[i].String())
	}
	u := get(0)
	ip := get(1)
	title := get(2)
	port := 0
	if len(arr) > 3 {
		port = int(arr[3].Int())
	}
	protocol := ""
	if len(arr) > 5 {
		protocol = strings.ToLower(get(5))
	}

	host := ""
	if u != "" {
		s := u
		if !strings.Contains(s, "://") {
			s = "http://" + s
		}
		if pu, err := url.Parse(s); err == nil {
			host = strings.ToLower(pu.Hostname())
		}
	}

	if ip == "" && u == "" && host == "" {
		return nil
	}
	a := models.NewAsset().
		WithIP(ip).
		WithPort(port).
		WithProtocol(protocol).
		WithHost(host).
		WithDomain(host).
		WithURL(u).
		WithTitle(title).
		WithSource(srcName).
		WithTags("bdziyi", "fofa-proxy")
	return a
}
