package hunter

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
	defaultHunterURL = "https://hunter.qianxin.com/openApi/search"
	defaultSize      = 100
)

// Hunter 实现 Hunter 引擎
type Hunter struct {
	*engine.BaseEngine
	client  *req.Client
	baseURL string
}

// NewHunter 创建 Hunter 引擎
func NewHunter() *Hunter {
	h := &Hunter{
		BaseEngine: engine.NewBaseEngine("hunter"),
		baseURL:    defaultHunterURL,
	}
	return h
}

// Name 返回引擎名称
func (h *Hunter) Name() string {
	return h.BaseEngine.Name()
}

// SetProxy 设置代理
func (h *Hunter) SetProxy(proxy string) {
	h.BaseEngine.SetProxy(proxy)
	h.buildClient()
}

// SetTimeout 设置超时
func (h *Hunter) SetTimeout(timeout time.Duration) {
	h.BaseEngine.SetTimeout(timeout)
	h.buildClient()
}

// SetKey 设置 API Key
func (h *Hunter) SetKey(key string) {
	h.BaseEngine.SetKey(key)
	h.buildClient()
}

// SetKeys 设置多个 API Key
func (h *Hunter) SetKeys(keys []string) {
	h.BaseEngine.SetKeys(keys)
	h.buildClient()
}

// buildClient 构建 HTTP 客户端
func (h *Hunter) buildClient() {
	c := req.C()
	c.SetTimeout(h.BaseEngine.Timeout())
	if h.BaseEngine.Proxy() != "" {
		c.SetProxyURL(h.BaseEngine.Proxy())
	}
	c.SetUserAgent(h.BaseEngine.UserAgent())
	h.client = c
}

// Search 执行搜索
func (h *Hunter) Search(ctx context.Context, query string, opts ...engine.SearchOption) ([]*models.Asset, error) {
	if h.client == nil {
		h.buildClient()
	}
	cfg := &engine.SearchConfig{
		Size:     defaultSize,
		MaxTotal: 5000,
		Timeout:  h.BaseEngine.Timeout(),
	}
	for _, opt := range opts {
		opt(cfg)
	}

	var allAssets []*models.Asset
	page := 1
	for len(allAssets) < cfg.MaxTotal {
		// 构造请
		u, err := url.Parse(h.baseURL)
		if err != nil {
			return nil, fmt.Errorf("parse url: %w", err)
		}
		// Hunter API 要求 search 参数为 URL-safe base64 编码（不是 raw 字符串）
		// 否则服务端返回 "URLBase64转码错误"
		q := u.Query()
		q.Set("api-key", h.BaseEngine.CurrentKey())
		q.Set("search", base64.URLEncoding.EncodeToString([]byte(query)))
		q.Set("page", strconv.Itoa(page))
		q.Set("page_size", strconv.Itoa(cfg.Size))
		q.Set("is_web", "3")
		u.RawQuery = q.Encode()

		// 发起请求
		resp, err := h.client.R().
			SetContext(ctx).
			Get(u.String())
		if err != nil {
			// 尝试轮换 Key 重试
			if len(h.BaseEngine.Keys()) > 1 {
				h.BaseEngine.RotateKey()
				h.buildClient()
				resp, err = h.client.R().
					SetContext(ctx).
					Get(u.String())
			}
			if err != nil {
				return nil, fmt.Errorf("request hunter: %w", err)
			}
		}

		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("hunter api status %d", resp.StatusCode)
		}

		body := resp.String()
		if !gjson.Valid(body) {
			return nil, fmt.Errorf("invalid json")
		}

		// 解析结果
		data := gjson.Parse(body)
		if data.Get("code").Int() != 200 {
			return nil, fmt.Errorf("hunter api error: %s", data.Get("message").String())
		}

		items := data.Get("data.arr").Array()
		if len(items) == 0 {
			break
		}

		for _, item := range items {
			ip := item.Get("ip").String()
			port := item.Get("port").Int()
			host := item.Get("host").String()
			protocol := item.Get("protocol").String()
			title := item.Get("web.title").String()
			server := item.Get("web.server").String()
			country := item.Get("location.country_cn").String()
			city := item.Get("location.city_cn").String()
			asset := models.NewAsset().
				WithTitle(fmt.Sprintf("[%s] %s:%d (%s)", h.Name(), ip, port, title)).
				WithHost(host).
				WithIP(ip).
				WithPort(int(port)).
				WithProtocol(protocol).
				WithTitle(title).
				WithServer(server).
				WithCountry(country).
				WithCity(city).
				WithSource(h.Name()).
				WithTags("engine", "hunter").
				WithRaw("protocol", protocol).
				WithRaw("title", title).
				WithRaw("server", server).
				WithRaw("country", country).
				WithRaw("city", city)
			allAssets = append(allAssets, asset)
		}

		// 检查是否还有更多页
		if len(items) < cfg.Size {
			break
		}
		page++
		time.Sleep(1 * time.Second)
	}

	// 限制总数
	if len(allAssets) > cfg.MaxTotal {
		allAssets = allAssets[:cfg.MaxTotal]
	}
	return allAssets, nil
}
