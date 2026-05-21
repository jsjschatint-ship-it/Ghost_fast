package core

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/wgpsec/ENScan/pkg/models"
	"gopkg.in/yaml.v3"
)

// Runner 统一调度入口（根据 config 启用引擎，并行查询，归一+去重+打标）
type Runner struct {
	engines map[string]Engine
	config  *Config
	deduper *Deduper
}

// Engine 引擎接口（与 pkg/engine/engine.go 保持一致）
type Engine interface {
	Name() string
	Search(ctx context.Context, query string, opts ...SearchOption) ([]*models.Asset, error)
	SetKey(key string)
	SetKeys(keys []string)
	SetProxy(proxy string)
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
	Fields    []string
}

// Config 运行器配置
type Config struct {
	Engines map[string]EngineConfig `yaml:"engines"`
	Proxy   string                  `yaml:"proxy"`
	Timeout int                     `yaml:"timeout"` // seconds
	Extra   map[string]any          `yaml:"extra"`
}

// EngineConfig 引擎配置
type EngineConfig struct {
	Key     string   `yaml:"key"`
	Keys    []string `yaml:"keys"`
	Email   string   `yaml:"email"`
	Emails  []string `yaml:"emails"`
	Proxy   string   `yaml:"proxy"`
	Timeout int      `yaml:"timeout"`
	Size    int      `yaml:"size"`
	Enabled bool     `yaml:"enabled"`
}

// NewRunner 创建运行器
func NewRunner(cfg *Config, engines map[string]Engine) *Runner {
	r := &Runner{
		engines: engines,
		config:  cfg,
		deduper: NewDeduper(KeySmart),
	}
	// 初始化引擎配置
	for name, eng := range engines {
		if ec, ok := cfg.Engines[name]; ok && ec.Enabled {
			if len(ec.Keys) > 0 {
				eng.SetKeys(ec.Keys)
			} else if ec.Key != "" {
				eng.SetKey(ec.Key)
			}
			if ec.Proxy != "" {
				eng.SetProxy(ec.Proxy)
			}
			if ec.Timeout > 0 {
				eng.SetTimeout(time.Duration(ec.Timeout) * time.Second)
			}
		}
	}
	return r
}

// Run 执行查询
func (r *Runner) Run(ctx context.Context, query string) ([]*models.Asset, error) {
	var wg sync.WaitGroup
	var mu sync.Mutex
	var allAssets []*models.Asset

	for name, eng := range r.engines {
		if ec, ok := r.config.Engines[name]; ok && ec.Enabled {
			wg.Add(1)
			go func(name string, eng Engine) {
				defer wg.Done()
				assets, err := eng.Search(ctx, query)
				if err != nil {
					// 可记录日志，此处静默跳过
					return
				}
				mu.Lock()
				allAssets = append(allAssets, assets...)
				mu.Unlock()
			}(name, eng)
		}
	}
	wg.Wait()

	// 去重
	deduped := r.deduper.Dedup(allAssets)

	// 打标（可选）
	// tag_all(deduped)

	return deduped, nil
}

// LoadKeysFile 从外部文件读取多 key（支持 txt/json/yaml）
func LoadKeysFile(path string) ([]string, error) {
	if path == "" {
		return nil, nil
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, nil
	}
	ext := strings.ToLower(filepath.Ext(path))
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read keys file: %w", err)
	}
	content := string(data)
	switch ext {
	case ".json":
		var keys []string
		if err := json.Unmarshal(data, &keys); err != nil {
			return nil, fmt.Errorf("parse json keys: %w", err)
		}
		return cleanKeys(keys), nil
	case ".yaml", ".yml":
		var keys []string
		if err := yaml.Unmarshal(data, &keys); err != nil {
			return nil, fmt.Errorf("parse yaml keys: %w", err)
		}
		return cleanKeys(keys), nil
	default:
		// 纯文本：每行一个
		lines := strings.Split(content, "\n")
		var out []string
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			// 去掉行内注释
			if idx := strings.Index(line, "#"); idx != -1 {
				line = strings.TrimSpace(line[:idx])
			}
			if line != "" {
				out = append(out, line)
			}
		}
		return out, nil
	}
}

// cleanKeys 清理 key 列表（去空、去空格）
func cleanKeys(keys []string) []string {
	var out []string
	for _, k := range keys {
		k = strings.TrimSpace(k)
		if k != "" {
			out = append(out, k)
		}
	}
	return out
}
