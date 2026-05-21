package shodan

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
	defaultShodanURL = "https://api.shodan.io"
	defaultSize      = 100
)

// Shodan 实现 Shodan 引擎
type Shodan struct {
	*engine.BaseEngine
	client  *req.Client
	baseURL string
}

// NewShodan 创建 Shodan 引擎
func NewShodan() *Shodan {
	s := &Shodan{
		BaseEngine: engine.NewBaseEngine("shodan"),
		baseURL:    defaultShodanURL,
	}
	return s
}

// Name 返回引擎名称
func (s *Shodan) Name() string {
	return s.BaseEngine.Name()
}

// SetProxy 设置代理
func (s *Shodan) SetProxy(proxy string) {
	s.BaseEngine.SetProxy(proxy)
	s.buildClient()
}

// SetTimeout 设置超时
func (s *Shodan) SetTimeout(timeout time.Duration) {
	s.BaseEngine.SetTimeout(timeout)
	s.buildClient()
}

// SetKey 设置 API Key
func (s *Shodan) SetKey(key string) {
	s.BaseEngine.SetKey(key)
	s.buildClient()
}

// SetKeys 设置多个 API Key
func (s *Shodan) SetKeys(keys []string) {
	s.BaseEngine.SetKeys(keys)
	s.buildClient()
}

// buildClient 构建 HTTP 客户端
func (s *Shodan) buildClient() {
	c := req.C()
	c.SetTimeout(s.BaseEngine.Timeout())
	if s.BaseEngine.Proxy() != "" {
		c.SetProxyURL(s.BaseEngine.Proxy())
	}
	c.SetUserAgent(s.BaseEngine.UserAgent())
	s.client = c
}

// Search 执行搜索
func (s *Shodan) Search(ctx context.Context, query string, opts ...engine.SearchOption) ([]*models.Asset, error) {
	if s.client == nil {
		s.buildClient()
	}
	cfg := &engine.SearchConfig{
		Size:     defaultSize,
		MaxTotal: 5000,
		Timeout:  s.BaseEngine.Timeout(),
	}
	for _, opt := range opts {
		opt(cfg)
	}

	var allAssets []*models.Asset
	page := 1
	for len(allAssets) < cfg.MaxTotal {
		// 构造请
		u, err := url.Parse(s.baseURL + "/shodan/host/search")
		if err != nil {
			return nil, fmt.Errorf("parse url: %w", err)
		}
		q := u.Query()
		q.Set("key", s.BaseEngine.CurrentKey())
		q.Set("query", query)
		q.Set("limit", strconv.Itoa(cfg.Size))
		q.Set("page", strconv.Itoa(page))
		u.RawQuery = q.Encode()

		// 发起请求
		resp, err := s.client.R().
			SetContext(ctx).
			Get(u.String())
		if err != nil {
			// 尝试轮换 Key 重试
			if len(s.BaseEngine.Keys()) > 1 {
				s.BaseEngine.RotateKey()
				s.buildClient()
				resp, err = s.client.R().
					SetContext(ctx).
					Get(u.String())
			}
			if err != nil {
				return nil, fmt.Errorf("request shodan: %w", err)
			}
		}

		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("shodan api status %d", resp.StatusCode)
		}

		body := resp.String()
		if !gjson.Valid(body) {
			return nil, fmt.Errorf("invalid json")
		}

		// 解析结果
		data := gjson.Parse(body)
		if data.Get("error").String() != "" {
			return nil, fmt.Errorf("shodan api error: %s", data.Get("error").String())
		}

		items := data.Get("matches").Array()
		if len(items) == 0 {
			break
		}

		for _, item := range items {
			ip := item.Get("ip_str").String()
			port := item.Get("port").Int()
			host := item.Get("hostnames").Array()
			var hostname string
			if len(host) > 0 {
				hostname = host[0].String()
			}
			title := item.Get("title").String()
			product := item.Get("product").String()
			asset := models.NewAsset().
				WithTitle(fmt.Sprintf("[%s] %s:%d (%s)", s.Name(), ip, port, title)).
				WithHost(hostname).
				WithIP(ip).
				WithSource(s.Name()).
				WithTags("engine", "shodan").
				WithRaw("port", strconv.Itoa(int(port))).
				WithRaw("title", title).
				WithRaw("product", product).
				WithRaw("country", item.Get("location.country_name").String()).
				WithRaw("os", item.Get("os").String())
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
