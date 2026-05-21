package quake

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/imroc/req/v3"
	"github.com/tidwall/gjson"
	"github.com/wgpsec/ENScan/pkg/engine"
	"github.com/wgpsec/ENScan/pkg/models"
)

const (
	defaultQuakeURL = "https://quake.360.cn/api/v3/search/quake_service"
	defaultSize     = 100
)

// Quake 实现 Quake 引擎
type Quake struct {
	*engine.BaseEngine
	client  *req.Client
	baseURL string
}

// NewQuake 创建 Quake 引擎
func NewQuake() *Quake {
	q := &Quake{
		BaseEngine: engine.NewBaseEngine("quake"),
		baseURL:    defaultQuakeURL,
	}
	return q
}

// Name 返回引擎名称
func (q *Quake) Name() string {
	return q.BaseEngine.Name()
}

// SetProxy 设置代理
func (q *Quake) SetProxy(proxy string) {
	q.BaseEngine.SetProxy(proxy)
	q.buildClient()
}

// SetTimeout 设置超时
func (q *Quake) SetTimeout(timeout time.Duration) {
	q.BaseEngine.SetTimeout(timeout)
	q.buildClient()
}

// SetKey 设置 API Key
func (q *Quake) SetKey(key string) {
	q.BaseEngine.SetKey(key)
	q.buildClient()
}

// SetKeys 设置多个 API Key
func (q *Quake) SetKeys(keys []string) {
	q.BaseEngine.SetKeys(keys)
	q.buildClient()
}

// buildClient 构建 HTTP 客户端
func (q *Quake) buildClient() {
	c := req.C()
	c.SetTimeout(q.BaseEngine.Timeout())
	if q.BaseEngine.Proxy() != "" {
		c.SetProxyURL(q.BaseEngine.Proxy())
	}
	c.SetUserAgent(q.BaseEngine.UserAgent())
	q.client = c
}

// Search 执行搜索
func (q *Quake) Search(ctx context.Context, query string, opts ...engine.SearchOption) ([]*models.Asset, error) {
	if q.client == nil {
		q.buildClient()
	}
	cfg := &engine.SearchConfig{
		Size:     defaultSize,
		MaxTotal: 5000,
		Timeout:  q.BaseEngine.Timeout(),
	}
	for _, opt := range opts {
		opt(cfg)
	}

	var allAssets []*models.Asset
	start := 0
	for len(allAssets) < cfg.MaxTotal {
		// 构造请
		payload := map[string]any{
			"query": query,
			"start": start,
			"size":  cfg.Size,
		}
		resp, err := q.client.R().
			SetContext(ctx).
			SetHeader("Content-Type", "application/json").
			SetHeader("X-QuakeToken", q.BaseEngine.CurrentKey()).
			SetBodyJsonMarshal(payload).
			Post(q.baseURL)
		if err != nil {
			// 尝试轮换 Key 重试
			if len(q.BaseEngine.Keys()) > 1 {
				q.BaseEngine.RotateKey()
				q.buildClient()
				resp, err = q.client.R().
					SetContext(ctx).
					SetHeader("Content-Type", "application/json").
					SetHeader("X-QuakeToken", q.BaseEngine.CurrentKey()).
					SetBodyJsonMarshal(payload).
					Post(q.baseURL)
			}
			if err != nil {
				return nil, fmt.Errorf("request quake: %w", err)
			}
		}

		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("quake api status %d", resp.StatusCode)
		}

		body := resp.String()
		if !gjson.Valid(body) {
			return nil, fmt.Errorf("invalid json")
		}

		// 解析结果
		data := gjson.Parse(body)
		if data.Get("code").Int() != 0 {
			return nil, fmt.Errorf("quake api error: %s", data.Get("message").String())
		}

		items := data.Get("data").Array()
		if len(items) == 0 {
			break
		}

		for _, item := range items {
			service := item.Get("service")
			host := service.Get("name").String()
			ip := item.Get("ip").String()
			port := service.Get("port").Int()
			title := item.Get("service.title").String()
			asset := models.NewAsset().
				WithTitle(fmt.Sprintf("[%s] %s:%d (%s)", q.Name(), ip, port, title)).
				WithHost(host).
				WithIP(ip).
				WithSource(q.Name()).
				WithTags("engine", "quake").
				WithRaw("port", strconv.Itoa(int(port))).
				WithRaw("title", title).
				WithRaw("country", item.Get("location.country_cn").String()).
				WithRaw("province", item.Get("location.province_cn").String())
			allAssets = append(allAssets, asset)
		}

		// 检查是否还有更多页
		if len(items) < cfg.Size {
			break
		}
		start += cfg.Size
		time.Sleep(1 * time.Second)
	}

	// 限制总数
	if len(allAssets) > cfg.MaxTotal {
		allAssets = allAssets[:cfg.MaxTotal]
	}
	return allAssets, nil
}
