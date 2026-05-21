package fofa

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/imroc/req/v3"
	"github.com/tidwall/gjson"
	"github.com/wgpsec/ENScan/pkg/engine"
	"github.com/wgpsec/ENScan/pkg/models"
)

const (
	defaultBaseURL = "https://fofa.info"
	defaultSize    = 100
)

// FOFA 实现 FOFA 引擎
type FOFA struct {
	*engine.BaseEngine
	client  *req.Client
	baseURL string
}

// NewFOFA 创建 FOFA 引擎
func NewFOFA() *FOFA {
	f := &FOFA{
		BaseEngine: engine.NewBaseEngine("fofa"),
		baseURL:    defaultBaseURL,
	}
	return f
}

// Name 返回引擎名称
func (f *FOFA) Name() string {
	return f.BaseEngine.Name()
}

// SetProxy 设置代理
func (f *FOFA) SetProxy(proxy string) {
	f.BaseEngine.SetProxy(proxy)
	f.buildClient()
}

// SetTimeout 设置超时
func (f *FOFA) SetTimeout(timeout time.Duration) {
	f.BaseEngine.SetTimeout(timeout)
	f.buildClient()
}

// SetKey 设置 API Key
func (f *FOFA) SetKey(key string) {
	f.BaseEngine.SetKey(key)
	f.buildClient()
}

// SetKeys 设置多个 API Key
func (f *FOFA) SetKeys(keys []string) {
	f.BaseEngine.SetKeys(keys)
	f.buildClient()
}

// buildClient 构建 HTTP 客户端
func (f *FOFA) buildClient() {
	c := req.C()
	c.SetTimeout(f.BaseEngine.Timeout())
	if f.BaseEngine.Proxy() != "" {
		c.SetProxyURL(f.BaseEngine.Proxy())
	}
	c.SetUserAgent(f.BaseEngine.UserAgent())
	f.client = c
}

// Search 执行搜索
func (f *FOFA) Search(ctx context.Context, query string, opts ...engine.SearchOption) ([]*models.Asset, error) {
	if f.client == nil {
		f.buildClient()
	}
	cfg := &engine.SearchConfig{
		Size:     defaultSize,
		MaxTotal: 5000,
		Timeout:  f.BaseEngine.Timeout(),
	}
	for _, opt := range opts {
		opt(cfg)
	}

	var allAssets []*models.Asset
	page := 1
	for len(allAssets) < cfg.MaxTotal {
		// 构造请
		u, err := url.Parse(f.baseURL + "/api/v1/search/all")
		if err != nil {
			return nil, fmt.Errorf("parse url: %w", err)
		}
		q := u.Query()
		q.Set("key", f.BaseEngine.CurrentKey())
		q.Set("qbase64", base64Encode(query))
		q.Set("size", strconv.Itoa(cfg.Size))
		q.Set("page", strconv.Itoa(page))
		q.Set("fields", "host,ip,port,title,domain,country,as_org,server,protocol")
		u.RawQuery = q.Encode()

		// 发起请求
		resp, err := f.client.R().
			SetContext(ctx).
			SetHeader("Accept", "application/json").
			Get(u.String())
		if err != nil {
			// 尝试轮换 Key 重试
			if len(f.BaseEngine.Keys()) > 1 {
				f.BaseEngine.RotateKey()
				f.buildClient()
				resp, err = f.client.R().
					SetContext(ctx).
					SetHeader("Accept", "application/json").
					Get(u.String())
			}
			if err != nil {
				return nil, fmt.Errorf("request fofa: %w", err)
			}
		}

		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("fofa api status %d", resp.StatusCode)
		}

		body := resp.String()
		if !gjson.Valid(body) {
			return nil, fmt.Errorf("invalid json")
		}

		// 解析结果
		data := gjson.Parse(body)
		if data.Get("error").Bool() {
			return nil, fmt.Errorf("fofa api error: %s", data.Get("errmsg").String())
		}

		items := data.Get("results").Array()
		if len(items) == 0 {
			break
		}

		// FOFA 带 fields 参数时 results 是 [[]string] 形式，
		// 每行字段顺序与 fields 参数完全一致：
		//   host, ip, port, title, domain, country, as_org, server, protocol
		for _, item := range items {
			row := item.Array()
			if len(row) < 9 {
				continue
			}
			host := row[0].String()
			ip := row[1].String()
			portStr := row[2].String()
			title := row[3].String()
			domain := row[4].String()
			country := row[5].String()
			asOrg := row[6].String()
			server := row[7].String()
			protocol := row[8].String()

			asset := models.NewAsset().
				WithHost(host).
				WithIP(ip).
				WithTitle(title).
				WithDomain(domain).
				WithSource(f.Name()).
				WithTags("engine", "fofa").
				WithRaw("country", country).
				WithRaw("as_org", asOrg).
				WithRaw("server", server).
				WithRaw("protocol", protocol)
			if port, err := strconv.Atoi(portStr); err == nil && port > 0 {
				asset.WithPort(port)
			}
			allAssets = append(allAssets, asset)
		}

		// 检查是否还有更多页
		if len(items) < cfg.Size {
			break
		}
		page++

		// 简单延
		time.Sleep(1 * time.Second)
	}

	// 限制总数
	if len(allAssets) > cfg.MaxTotal {
		allAssets = allAssets[:cfg.MaxTotal]
	}
	return allAssets, nil
}

// base64Encode 标准 base64 编码
func base64Encode(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}
