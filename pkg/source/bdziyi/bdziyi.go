package bdziyi

// bdziyi.com 蹭数据合集。三种模式共用结构体：
//   bdziyi_fofa: FOFA 代理（POST /hygj/ssyqapi*.php）
//   bdziyi_ze  : ZoomEye 代理（POST /hygj/zeyq/search.php）
//   bdziyi_icp : 工信部 ICP 异步备案查询（POST query → poll）
// 需要 bdziyi.com 登录后的 Cookie；三种模式共用同一份 Cookie。
// 流量只到 bdziyi.com，不向目标发请求。

import (
	"context"
	"fmt"
	"time"

	"github.com/imroc/req/v3"
	"github.com/wgpsec/ENScan/pkg/models"
	"github.com/wgpsec/ENScan/pkg/source"
)

const (
	bdHomeFOFA = "https://bdziyi.com/hygj/ssyq.html"
	bdHomeZE   = "https://bdziyi.com/hygj/zeyq/"
	bdHomeICP  = "https://bdziyi.com/icp/"
	bdOrigin   = "https://bdziyi.com"
	bdUA       = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
		"(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

// BDZiyi 三种模式公用结构体；mode 决定使用哪条 search 流程。
type BDZiyi struct {
	*source.BaseSource
	client *req.Client
	mode   string // "fofa" | "icp" | "ze"
}

// NewBDZiyi 内部构造器
func NewBDZiyi(mode string) *BDZiyi {
	return &BDZiyi{
		BaseSource: source.NewBaseSource("bdziyi_" + mode),
		client:     req.C().SetTimeout(60 * time.Second).SetUserAgent(bdUA),
		mode:       mode,
	}
}

// 便捷构造器
func NewBDZiyiFOFA() *BDZiyi { return NewBDZiyi("fofa") }
func NewBDZiyiICP() *BDZiyi  { return NewBDZiyi("icp") }
func NewBDZiyiZE() *BDZiyi   { return NewBDZiyi("ze") }

// Name 数据源名
func (s *BDZiyi) Name() string { return s.BaseSource.Name() }

// NeedsKey 是否需要 API Key
func (s *BDZiyi) NeedsKey() bool { return false }

// Accepts 接受的输入类型
func (s *BDZiyi) Accepts() []string {
	switch s.mode {
	case "icp":
		return []string{"domain", "company", "keyword"}
	default:
		return []string{"domain"}
	}
}

// cookie 提取 Cookie，优先 cfg.cookie；兼容 cfg.cookies.bdziyi
func (s *BDZiyi) cookie() string {
	cfg := s.BaseSource.Config()
	if cfg == nil {
		return ""
	}
	if v, ok := cfg["cookie"].(string); ok && v != "" {
		return v
	}
	if cs, ok := cfg["cookies"].(map[string]any); ok {
		if v, ok2 := cs["bdziyi"].(string); ok2 && v != "" {
			return v
		}
	}
	return ""
}

// configInt 安全取 int
func (s *BDZiyi) configInt(key string, def int) int {
	cfg := s.BaseSource.Config()
	if cfg == nil {
		return def
	}
	switch v := cfg[key].(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	}
	return def
}

// configString 安全取 string
func (s *BDZiyi) configString(key, def string) string {
	cfg := s.BaseSource.Config()
	if cfg == nil {
		return def
	}
	if v, ok := cfg[key].(string); ok && v != "" {
		return v
	}
	return def
}

// configBool 安全取 bool
func (s *BDZiyi) configBool(key string) bool {
	cfg := s.BaseSource.Config()
	if cfg == nil {
		return false
	}
	switch v := cfg[key].(type) {
	case bool:
		return v
	case string:
		return v == "true" || v == "1" || v == "yes"
	}
	return false
}

// baseHeaders 通用请求头（不含 Cookie）
func (s *BDZiyi) baseHeaders(referer, contentType string) map[string]string {
	h := map[string]string{
		"User-Agent": bdUA,
		"Referer":    referer,
		"Origin":     bdOrigin,
		"Accept":     "application/json, text/plain, */*",
	}
	if contentType != "" {
		h["Content-Type"] = contentType
	}
	return h
}

// errAsset 把错误信息封成一条带 tags=error 的 Asset 返给上层（与 Python 版行为一致）。
func (s *BDZiyi) errAsset(format string, a ...any) *models.Asset {
	return models.NewAsset().
		WithTitle(fmt.Sprintf("[%s] "+format, append([]any{s.Name()}, a...)...)).
		WithSource(s.Name()).
		WithTags("error", "bdziyi")
}

// Search 执行搜索
func (s *BDZiyi) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	cfg := &source.SearchConfig{MaxAssets: 500}
	for _, opt := range opts {
		opt(cfg)
	}
	if target == "" {
		return nil, nil
	}
	switch s.mode {
	case "fofa":
		return s.searchFOFA(ctx, target, cfg)
	case "ze":
		return s.searchZE(ctx, target, cfg)
	case "icp":
		return s.searchICP(ctx, target, cfg)
	}
	return nil, fmt.Errorf("bdziyi: unknown mode %q", s.mode)
}
