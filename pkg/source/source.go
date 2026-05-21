package source

import (
	"context"

	"github.com/wgpsec/ENScan/pkg/models"
)

// Source 定义被动数据源接口
type Source interface {
	// Name 数据源名称
	Name() string
	// Accepts 接受的输入类型
	Accepts() []string
	// Search 执行搜索
	Search(ctx context.Context, target string, opts ...SearchOption) ([]*models.Asset, error)
	// SetConfig 设置配置项（来自 config.yaml）
	SetConfig(cfg map[string]any) error
	// NeedsKey 是否需要 API Key
	NeedsKey() bool
	// SetKey 设置 API Key（如果需要）
	SetKey(key string)
}

// SearchOption 搜索选项
type SearchOption func(*SearchConfig)

// SearchConfig 搜索配置
type SearchConfig struct {
	MaxAssets    int
	EnableTypes  []string
	DisableTypes []string
	Extra        map[string]any
}

// WithMaxAssets 设置最大资产数
func WithMaxAssets(n int) SearchOption {
	return func(c *SearchConfig) {
		c.MaxAssets = n
	}
}

// WithEnableTypes 启用类型白名单
func WithEnableTypes(types ...string) SearchOption {
	return func(c *SearchConfig) {
		c.EnableTypes = append(c.EnableTypes, types...)
	}
}

// WithDisableTypes 禁用类型黑名单
func WithDisableTypes(types ...string) SearchOption {
	return func(c *SearchConfig) {
		c.DisableTypes = append(c.DisableTypes, types...)
	}
}

// WithExtra 设置额外参数
func WithExtra(key string, value any) SearchOption {
	return func(c *SearchConfig) {
		if c.Extra == nil {
			c.Extra = make(map[string]any)
		}
		c.Extra[key] = value
	}
}

// BaseSource 基础数据源实现
type BaseSource struct {
	name string
	cfg  map[string]any
	key  string
}

// NewBaseSource 创建基础数据源
func NewBaseSource(name string) *BaseSource {
	return &BaseSource{
		name: name,
		cfg:  make(map[string]any),
	}
}

// Name 返回数据源名称
func (s *BaseSource) Name() string {
	return s.name
}

// SetConfig 设置配置
func (s *BaseSource) SetConfig(cfg map[string]any) error {
	s.cfg = cfg
	// 自动抽取常见 key 字段，便于 BaseSource.Key() 取用
	if v, ok := cfg["key"].(string); ok && v != "" {
		s.key = v
	} else if keys, ok := cfg["keys"].([]string); ok && len(keys) > 0 {
		s.key = keys[0]
	} else if keys, ok := cfg["keys"].([]any); ok && len(keys) > 0 {
		if k, ok2 := keys[0].(string); ok2 {
			s.key = k
		}
	}
	return nil
}

// NeedsKey 是否需要 API Key
func (s *BaseSource) NeedsKey() bool {
	return false
}

// SetKey 设置 Key
func (s *BaseSource) SetKey(key string) {
	s.key = key
}

// Key 返回 API Key
func (s *BaseSource) Key() string {
	return s.key
}

// Config 返回配置（只读）
func (s *BaseSource) Config() map[string]any {
	return s.cfg
}
