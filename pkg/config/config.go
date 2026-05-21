package config

import (
	"fmt"
	"os"

	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

// Config 全局配置
type Config struct {
	Runner  RunnerConfig            `yaml:"runner"`
	Engines map[string]EngineConfig `yaml:"engines"`
	Sources map[string]any          `yaml:"sources"`
	Extra   map[string]any          `yaml:"extra"`
}

// RunnerConfig 运行器配置
type RunnerConfig struct {
	EnabledSources []string       `yaml:"enabled"`
	Proxy          string         `yaml:"proxy"`
	UserAgent      string         `yaml:"user_agent"`
	MaxConcurrency int            `yaml:"max_concurrency"`
	Timeout        int            `yaml:"timeout"`
	Extra          map[string]any `yaml:"extra"`
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

// 已知引擎名（顶层条目命中这些会被归到 cfg.Engines）
var knownEngines = map[string]struct{}{
	"fofa": {}, "hunter": {}, "quake": {}, "zoomeye": {}, "shodan": {}, "zerozone": {},
}

// sourceAliases 把 yaml 顶层"组名"展开到多个具体的 source 注册名。
// 用户旧 yaml 习惯写 `github: { key: ... }`，但 registry 注册名其实是
// github_code / github_secrets / github_commits 等，需要把同一份配置
// 复制喂给每个 alias（仅当 alias 自己没显式配置时）。
var sourceAliases = map[string][]string{
	"github":     {"github_code", "github_secrets", "github_commits", "supply_github_org"},
	"intelx":     {"intelx", "intelx_leaks"},
	"hunter_io":  {"hunter_io", "hunter_verify"},
	"circl_pdns": {"pdns_circl"},
	"whoisxml":   {"whois_reverse"},
	"bdziyi":     {"bdziyi_ze", "bdziyi_fofa", "bdziyi_icp"},
}

// LoadFromFile 从文件加载配置。
// 同时兼容两种 yaml 风格：
//
//	A) 嵌套（推荐）：
//	   runner: { enabled: [...], proxy: ... }
//	   engines: { fofa: { key: ... } }
//	   sources: { chaos: { key: ... } }
//
//	B) 扁平（Python 兼容 / 旧版）：
//	   proxies:  { http: ..., https: ... }
//	   fofa:     { key: ... }
//	   chaos:    { key: ... }
//	   enabled:  { fofa: true, ... }
//
// 加载时会把 B 风格自动 merge 到 A schema 的对应位置，
// 用户旧的 config.yaml 不需要改动。
func LoadFromFile(path string) (*Config, error) {
	viper.SetConfigFile(path)
	viper.SetConfigType("yaml")
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			return defaultConfig(), nil
		}
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}
	mergeFlatLayout(&cfg, viper.AllSettings())
	return &cfg, nil
}

// mergeFlatLayout 把 Python 风格的扁平字段补到嵌套 schema 上。
// 永远不会覆盖嵌套 schema 已经填了的字段。
func mergeFlatLayout(cfg *Config, raw map[string]any) {
	if cfg.Engines == nil {
		cfg.Engines = make(map[string]EngineConfig)
	}
	if cfg.Sources == nil {
		cfg.Sources = make(map[string]any)
	}

	// 1) proxy 解析。优先级（高 → 低）：
	//    顶层 socks5 字符串 > 顶层 proxies.socks5 > 顶层 proxy > proxies.https > proxies.http
	// Go 的 http.ProxyFromEnvironment 原生识别 socks5:// scheme，
	// 写到 HTTPS_PROXY 环境变量里即可路由所有 https 请求走 SOCKS5。
	// 国内站点通过 NO_PROXY（含 .cn / 国内厂商域名）自动直连，不走代理。
	if cfg.Runner.Proxy == "" {
		if p, ok := raw["socks5"].(string); ok && p != "" {
			cfg.Runner.Proxy = ensureScheme(p, "socks5")
		} else if pm, ok := raw["proxies"].(map[string]any); ok {
			for _, k := range []string{"socks5", "https", "http"} {
				if v, ok2 := pm[k].(string); ok2 && v != "" {
					if k == "socks5" {
						cfg.Runner.Proxy = ensureScheme(v, "socks5")
					} else {
						cfg.Runner.Proxy = v
					}
					break
				}
			}
		}
		if cfg.Runner.Proxy == "" {
			if p, ok := raw["proxy"].(string); ok && p != "" {
				cfg.Runner.Proxy = p
			}
		}
	}

	// 2) 顶层 enabled 段（Python 风格）→ runner.EnabledSources + engines[*].Enabled
	if em, ok := raw["enabled"].(map[string]any); ok {
		for name, v := range em {
			if b, ok2 := v.(bool); ok2 {
				ec := cfg.Engines[name]
				ec.Enabled = b
				cfg.Engines[name] = ec
				if b && !contains(cfg.Runner.EnabledSources, name) {
					cfg.Runner.EnabledSources = append(cfg.Runner.EnabledSources, name)
				}
			}
		}
	}

	// 3) 顶层每个 map：是已知引擎 → engines[name]，否则 → sources[name]
	reservedTop := map[string]struct{}{
		"runner": {}, "engines": {}, "sources": {}, "extra": {},
		"proxies": {}, "proxy": {}, "socks5": {}, "enabled": {},
	}
	for k, v := range raw {
		if _, isReserved := reservedTop[k]; isReserved {
			continue
		}
		m, isMap := v.(map[string]any)
		if !isMap {
			continue
		}
		if _, isEngine := knownEngines[k]; isEngine {
			ec := cfg.Engines[k]
			fillEngine(&ec, m)
			cfg.Engines[k] = ec
			continue
		}
		// alias 展开：一个组名 → 多个 source 注册名（仅在 alias 没显式配置时填）
		if aliases, ok := sourceAliases[k]; ok {
			for _, alias := range aliases {
				if _, exists := cfg.Sources[alias]; !exists {
					cfg.Sources[alias] = m
				}
			}
			continue
		}
		if _, exists := cfg.Sources[k]; !exists {
			cfg.Sources[k] = m
		}
	}

	// 把已知 source 的"特殊命名 key"也补一遍（特别是 censys / circl_pdns 用 api_id/api_secret/user/pass）
	// 这部分仅靠 source 自身的 SetConfig 去解析，已经在 cfg.Sources 里。
}

// fillEngine 用 map 填充 EngineConfig（仅在原值为空时写入，便于 schema A 优先）
func fillEngine(ec *EngineConfig, m map[string]any) {
	if ec.Key == "" {
		if s, ok := m["key"].(string); ok {
			ec.Key = s
		}
	}
	if len(ec.Keys) == 0 {
		if arr, ok := m["keys"].([]any); ok {
			seen := map[string]bool{}
			for _, x := range arr {
				if s, ok2 := x.(string); ok2 && s != "" && !seen[s] {
					seen[s] = true
					ec.Keys = append(ec.Keys, s)
				}
			}
		}
	}
	if ec.Email == "" {
		if s, ok := m["email"].(string); ok {
			ec.Email = s
		}
	}
	if ec.Proxy == "" {
		if s, ok := m["proxy"].(string); ok {
			ec.Proxy = s
		}
	}
	if ec.Timeout == 0 {
		if n, ok := m["timeout"].(int); ok {
			ec.Timeout = n
		}
	}
	if ec.Size == 0 {
		if n, ok := m["size"].(int); ok {
			ec.Size = n
		}
	}
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// ensureScheme 给 proxy 字符串自动补 scheme 前缀。
// 用户可能写 "127.0.0.1:1080"（裸 host:port）或 "socks5://..."（已带 scheme）。
func ensureScheme(s, defaultScheme string) string {
	for _, p := range []string{"http://", "https://", "socks5://", "socks5h://", "socks4://"} {
		if len(s) >= len(p) && s[:len(p)] == p {
			return s
		}
	}
	return defaultScheme + "://" + s
}

// SaveToFile 保存配置到文件
func (c *Config) SaveToFile(path string) error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return nil
}

// defaultConfig 返回默认配置
func defaultConfig() *Config {
	return &Config{
		Runner: RunnerConfig{
			EnabledSources: []string{"fofa"},
			MaxConcurrency: 10,
			Timeout:        30,
		},
		Engines: map[string]EngineConfig{
			"fofa": {
				Enabled: true,
			},
		},
		Sources: make(map[string]any),
		Extra:   make(map[string]any),
	}
}

// GetEngineConfig 获取引擎配置
func (c *Config) GetEngineConfig(name string) EngineConfig {
	if cfg, ok := c.Engines[name]; ok {
		return cfg
	}
	return EngineConfig{}
}

// GetSourceConfig 获取数据源配置
func (c *Config) GetSourceConfig(name string) map[string]any {
	if cfg, ok := c.Sources[name]; ok {
		if m, ok := cfg.(map[string]any); ok {
			return m
		}
	}
	return make(map[string]any)
}
