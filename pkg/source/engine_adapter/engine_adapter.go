// Package engine_adapter 将 pkg/engine.Engine 适配为 source.Source 接口
package engine_adapter

import (
	"context"
	"time"

	"github.com/wgpsec/ENScan/pkg/engine"
	"github.com/wgpsec/ENScan/pkg/models"
	"github.com/wgpsec/ENScan/pkg/source"
)

// Adapter 将 engine.Engine 适配为 source.Source
type Adapter struct {
	*source.BaseSource
	engine engine.Engine
}

// New 创建适配器
func New(name string, e engine.Engine) *Adapter {
	return &Adapter{
		BaseSource: source.NewBaseSource(name),
		engine:     e,
	}
}

// Accepts 接受的输入类型
func (a *Adapter) Accepts() []string {
	return []string{"domain", "ip", "keyword", "company"}
}

// NeedsKey 是否需要 API Key
func (a *Adapter) NeedsKey() bool { return true }

// SetKey 透传到引擎
func (a *Adapter) SetKey(k string) {
	a.BaseSource.SetKey(k)
	a.engine.SetKey(k)
}

// SetConfig 解析 keys/key/proxy/timeout 并下发到引擎
func (a *Adapter) SetConfig(cfg map[string]any) error {
	_ = a.BaseSource.SetConfig(cfg)
	if v, ok := cfg["key"].(string); ok && v != "" {
		a.engine.SetKey(v)
	}
	if v, ok := cfg["keys"].([]string); ok && len(v) > 0 {
		a.engine.SetKeys(v)
	} else if v, ok := cfg["keys"].([]any); ok {
		keys := make([]string, 0, len(v))
		for _, k := range v {
			if s, ok := k.(string); ok {
				keys = append(keys, s)
			}
		}
		if len(keys) > 0 {
			a.engine.SetKeys(keys)
		}
	}
	if v, ok := cfg["proxy"].(string); ok && v != "" {
		a.engine.SetProxy(v)
	}
	if v, ok := cfg["timeout"].(int); ok && v > 0 {
		a.engine.SetTimeout(time.Duration(v) * time.Second)
	}
	return nil
}

// Search 执行搜索
// MaxAssets 默认 0 = 不限，由 engine 内部默认（fofa.MaxTotal=5000、shodan/zoomeye 100 等）兜底；
// 仅当上层显式 WithMaxAssets(N>0) 才把 N 作为引擎分页停止条件 WithMaxTotal(N)。
func (a *Adapter) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	cfg := &source.SearchConfig{} // MaxAssets=0 表示"不限"，让引擎自己的默认值生效
	for _, opt := range opts {
		opt(cfg)
	}
	var engineOpts []engine.SearchOption
	if cfg.MaxAssets > 0 {
		engineOpts = append(engineOpts, engine.WithMaxTotal(cfg.MaxAssets))
	}
	return a.engine.Search(ctx, target, engineOpts...)
}
