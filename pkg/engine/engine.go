package engine

import (
	"context"
	"time"

	"github.com/wgpsec/ENScan/pkg/models"
)

// Engine 定义搜索引擎接口
type Engine interface {
	// Name 引擎名称
	Name() string
	// Search 执行搜索，返回资产列表
	Search(ctx context.Context, query string, opts ...SearchOption) ([]*models.Asset, error)
	// SetKey 设置 API Key
	SetKey(key string)
	// SetKeys 设置多个 API Key，支持轮换
	SetKeys(keys []string)
	// SetProxy 设置代理
	SetProxy(proxy string)
	// SetTimeout 设置超时
	SetTimeout(timeout time.Duration)
}

// SearchOption 搜索选项
type SearchOption func(*SearchConfig)

// SearchConfig 搜索配置
type SearchConfig struct {
	Size      int
	MaxTotal  int
	Timeout   time.Duration
	Proxy     string
	UserAgent string
	Fields    []string // 可选字段（适用于部分引擎）
}

// WithSize 设置每页大小
func WithSize(size int) SearchOption {
	return func(c *SearchConfig) {
		c.Size = size
	}
}

// WithMaxTotal 设置最大总数
func WithMaxTotal(maxTotal int) SearchOption {
	return func(c *SearchConfig) {
		c.MaxTotal = maxTotal
	}
}

// WithTimeout 设置超时
func WithTimeout(timeout time.Duration) SearchOption {
	return func(c *SearchConfig) {
		c.Timeout = timeout
	}
}

// WithProxy 设置代理
func WithProxy(proxy string) SearchOption {
	return func(c *SearchConfig) {
		c.Proxy = proxy
	}
}

// WithUserAgent 设置 UA
func WithUserAgent(ua string) SearchOption {
	return func(c *SearchConfig) {
		c.UserAgent = ua
	}
}

// WithFields 设置字段
func WithFields(fields ...string) SearchOption {
	return func(c *SearchConfig) {
		c.Fields = fields
	}
}

// BaseEngine 基础引擎实现
type BaseEngine struct {
	name      string
	keys      []string
	keyIdx    int
	timeout   time.Duration
	proxy     string
	userAgent string
}

// NewBaseEngine 创建基础引擎
func NewBaseEngine(name string) *BaseEngine {
	return &BaseEngine{
		name:      name,
		timeout:   30 * time.Second,
		userAgent: "Mozilla/5.0 (compatible; ENScan/1.0)",
	}
}

// Name 返回引擎名称
func (e *BaseEngine) Name() string {
	return e.name
}

// SetKey 设置单个 Key
func (e *BaseEngine) SetKey(key string) {
	e.keys = []string{key}
	e.keyIdx = 0
}

// SetKeys 设置多个 Key
func (e *BaseEngine) SetKeys(keys []string) {
	clean := make([]string, 0, len(keys))
	for _, k := range keys {
		if k != "" {
			clean = append(clean, k)
		}
	}
	e.keys = clean
	e.keyIdx = 0
}

// SetProxy 设置代理
func (e *BaseEngine) SetProxy(proxy string) {
	e.proxy = proxy
}

// SetTimeout 设置超时
func (e *BaseEngine) SetTimeout(timeout time.Duration) {
	e.timeout = timeout
}

// rotateKey 轮换 Key
func (e *BaseEngine) rotateKey() {
	if len(e.keys) > 1 {
		e.keyIdx = (e.keyIdx + 1) % len(e.keys)
	}
}

// currentKey 当前 Key
func (e *BaseEngine) currentKey() string {
	if len(e.keys) == 0 {
		return ""
	}
	return e.keys[e.keyIdx]
}

// 公开访问器（供子引擎包跨包使用）

// Timeout 返回超时
func (e *BaseEngine) Timeout() time.Duration { return e.timeout }

// Proxy 返回代理
func (e *BaseEngine) Proxy() string { return e.proxy }

// UserAgent 返回 UA
func (e *BaseEngine) UserAgent() string { return e.userAgent }

// SetUserAgent 设置 UA
func (e *BaseEngine) SetUserAgent(ua string) { e.userAgent = ua }

// Keys 返回所有 Key
func (e *BaseEngine) Keys() []string { return e.keys }

// CurrentKey 返回当前 Key
func (e *BaseEngine) CurrentKey() string { return e.currentKey() }

// RotateKey 轮换 Key
func (e *BaseEngine) RotateKey() { e.rotateKey() }
