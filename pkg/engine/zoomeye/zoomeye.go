package zoomeye

import (
	"context"
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
	defaultZoomEyeURL = "https://api.zoomeye.org"
	defaultSize       = 100
)

// ZoomEye 实现 ZoomEye 引擎
type ZoomEye struct {
	*engine.BaseEngine
	client  *req.Client
	baseURL string
}

// NewZoomEye 创建 ZoomEye 引擎
func NewZoomEye() *ZoomEye {
	z := &ZoomEye{
		BaseEngine: engine.NewBaseEngine("zoomeye"),
		baseURL:    defaultZoomEyeURL,
	}
	return z
}

// Name 返回引擎名称
func (z *ZoomEye) Name() string {
	return z.BaseEngine.Name()
}

// SetProxy 设置代理
func (z *ZoomEye) SetProxy(proxy string) {
	z.BaseEngine.SetProxy(proxy)
	z.buildClient()
}

// SetTimeout 设置超时
func (z *ZoomEye) SetTimeout(timeout time.Duration) {
	z.BaseEngine.SetTimeout(timeout)
	z.buildClient()
}

// SetKey 设置 API Key
func (z *ZoomEye) SetKey(key string) {
	z.BaseEngine.SetKey(key)
	z.buildClient()
}

// SetKeys 设置多个 API Key
func (z *ZoomEye) SetKeys(keys []string) {
	z.BaseEngine.SetKeys(keys)
	z.buildClient()
}

// buildClient 构建 HTTP 客户端
func (z *ZoomEye) buildClient() {
	c := req.C()
	c.SetTimeout(z.BaseEngine.Timeout())
	if z.BaseEngine.Proxy() != "" {
		c.SetProxyURL(z.BaseEngine.Proxy())
	}
	c.SetUserAgent(z.BaseEngine.UserAgent())
	z.client = c
}

// Search 执行搜索
func (z *ZoomEye) Search(ctx context.Context, query string, opts ...engine.SearchOption) ([]*models.Asset, error) {
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

	var allAssets []*models.Asset
	page := 1
	for len(allAssets) < cfg.MaxTotal {
		// 构造请
		u, err := url.Parse(z.baseURL + "/host/search")
		if err != nil {
			return nil, fmt.Errorf("parse url: %w", err)
		}
		q := u.Query()
		q.Set("query", query)
		q.Set("page", strconv.Itoa(page))
		u.RawQuery = q.Encode()

		// 发起请求（ZoomEye 通过 API-KEY 请求头鉴权）
		resp, err := z.client.R().
			SetContext(ctx).
			SetHeader("API-KEY", z.BaseEngine.CurrentKey()).
			Get(u.String())
		if err != nil {
			// 尝试轮换 Key 重试
			if len(z.BaseEngine.Keys()) > 1 {
				z.BaseEngine.RotateKey()
				z.buildClient()
				resp, err = z.client.R().
					SetContext(ctx).
					SetHeader("API-KEY", z.BaseEngine.CurrentKey()).
					Get(u.String())
			}
			if err != nil {
				return nil, fmt.Errorf("request zoomeye: %w", err)
			}
		}

		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("zoomeye api status %d", resp.StatusCode)
		}

		body := resp.String()
		if !gjson.Valid(body) {
			return nil, fmt.Errorf("invalid json")
		}

		// 解析结果
		data := gjson.Parse(body)
		if data.Get("error").String() != "" {
			return nil, fmt.Errorf("zoomeye api error: %s", data.Get("error").String())
		}

		items := data.Get("matches").Array()
		if len(items) == 0 {
			break
		}

		for _, item := range items {
			ip := item.Get("ip").String()
			port := item.Get("portinfo.port").Int()
			host := item.Get("domains").Array()
			var hostname string
			if len(host) > 0 {
				hostname = host[0].String()
			}
			title := item.Get("geoinfo.title").String()
			service := item.Get("portinfo.service").String()
			asset := models.NewAsset().
				WithTitle(fmt.Sprintf("[%s] %s:%d (%s)", z.Name(), ip, port, title)).
				WithHost(hostname).
				WithIP(ip).
				WithSource(z.Name()).
				WithTags("engine", "zoomeye").
				WithRaw("port", strconv.Itoa(int(port))).
				WithRaw("title", title).
				WithRaw("service", service).
				WithRaw("country", item.Get("geoinfo.country.names.en").String()).
				WithRaw("city", item.Get("geoinfo.city.names.en").String())
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
