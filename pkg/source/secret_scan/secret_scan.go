package secret_scan

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/wgpsec/ENScan/pkg/models"
	"github.com/wgpsec/ENScan/pkg/source"
)

// SecretScan 实现 Secret/Cloud-Key 正则扫描
type SecretScan struct {
	*source.BaseSource
	patterns []*pattern
}

type pattern struct {
	label    string
	severity string
	re       *regexp.Regexp
}

// NewSecretScan 创建 SecretScan
func NewSecretScan() *SecretScan {
	s := &SecretScan{
		BaseSource: source.NewBaseSource("secret_scan"),
		patterns:   buildPatterns(),
	}
	return s
}

// Name 返回名称
func (s *SecretScan) Name() string {
	return s.BaseSource.Name()
}

// Accepts 接受的输入类型
func (s *SecretScan) Accepts() []string {
	return []string{"domain", "company", "ip", "url"}
}

// NeedsKey 是否需要 API Key
func (s *SecretScan) NeedsKey() bool {
	return false
}

// SetConfig 设置配置
func (s *SecretScan) SetConfig(cfg map[string]any) error {
	_ = s.BaseSource.SetConfig(cfg)
	// 可根据配置动态加载/卸载 pattern
	return nil
}

// Search 执行搜索
func (s *SecretScan) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	cfg := &source.SearchConfig{
		MaxAssets: 500,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	// 输入来源（优先级）：
	// 1) cfg.Extra["texts"] []string — 上游 pipeline 注入的文本块
	// 2) target 自身被识别为 URL/纯文本时直接处理
	// 否则返回空（不再产生硬编码示例数据）
	var texts []string
	if cfg.Extra != nil {
		if v, ok := cfg.Extra["texts"].([]string); ok {
			texts = append(texts, v...)
		}
		if v, ok := cfg.Extra["texts"].([]any); ok {
			for _, x := range v {
				if s, ok2 := x.(string); ok2 {
					texts = append(texts, s)
				}
			}
		}
	}
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		// 简单 GET 抓取响应正文
		// 注意：此 source 没有自己的 http client；保守做法只收 cfg.Extra
		_ = target // intentionally skipped to keep secret_scan purely passive
	} else if !strings.Contains(target, "://") && len(target) < 4096 &&
		(strings.Contains(target, "=") || strings.Contains(target, "BEGIN ")) {
		// target 像 raw 文本片段
		texts = append(texts, target)
	}
	if len(texts) == 0 {
		return nil, nil
	}
	var allAssets []*models.Asset
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, txt := range texts {
		wg.Add(1)
		go func(text string) {
			defer wg.Done()
			for _, pat := range s.patterns {
				// 检查启用/禁用类型
				if len(cfg.EnableTypes) > 0 && !contains(cfg.EnableTypes, pat.label) {
					continue
				}
				if contains(cfg.DisableTypes, pat.label) {
					continue
				}
				for _, m := range pat.re.FindAllString(text, -1) {
					redacted := redact(m, pat.label)
					asset := models.NewAsset().
						WithTitle(fmt.Sprintf("[%s] %s", pat.label, redacted)).
						WithSource(s.Name()).
						WithTags("secret", pat.label, "severity:"+pat.severity).
						WithRaw("label", pat.label).
						WithRaw("severity", pat.severity).
						WithRaw("redacted", redacted)
					mu.Lock()
					allAssets = append(allAssets, asset)
					if len(allAssets) >= cfg.MaxAssets {
						mu.Unlock()
						return
					}
					mu.Unlock()
				}
			}
		}(txt)
	}
	wg.Wait()

	if len(allAssets) > cfg.MaxAssets {
		allAssets = allAssets[:cfg.MaxAssets]
	}
	return allAssets, nil
}

// buildPatterns 构建正则模式（从 Python 版移植）
func buildPatterns() []*pattern {
	return []*pattern{
		{"aws_access_key_id", "high", regexp.MustCompile(`(?i)aws[_\-]?access[_\-]?key[_\-]?id[=:]\s*([A-Z0-9]{20})`)},
		{"aws_secret_access_key", "high", regexp.MustCompile(`(?i)aws[_\-]?secret[_\-]?access[_\-]?key[=:]\s*([A-Za-z0-9+/]{40})`)},
		{"aws_session_token", "mid", regexp.MustCompile(`(?i)aws[_\-]?session[_\-]?token[=:]\s*([A-Za-z0-9+/]{16,})`)},
		{"google_application_credentials", "high", regexp.MustCompile(`(?i)google[_\-]?application[_\-]?credentials[=:]\s*["']?([^"'\s]+)["']?`)},
		{"azure_storage_key", "high", regexp.MustCompile(`(?i)azure[_\-]?storage[_\-]?key[=:]\s*([A-Za-z0-9+/]{88})`)},
		{"azure_client_secret", "high", regexp.MustCompile(`(?i)azure[_\-]?client[_\-]?secret[=:]\s*([A-Za-z0-9\-_]{36})`)},
		{"private_key_pem", "high", regexp.MustCompile(`(?i)-----begin\s+(?:rsa\s+)?private\s+key-----`)},
		{"private_key_ssh", "high", regexp.MustCompile(`(?i)ssh[_\-]?rsa[_\-]?private[_\-]?key[=:]\s*["']?([^"'\s]+)["']?`)},
		{"jwt_token", "mid", regexp.MustCompile(`eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*`)},
		{"database_uri", "mid", regexp.MustCompile(`(?i)(?:mysql|postgresql|mongodb|redis)://[^\s]+`)},
		{"openai_api_key", "high", regexp.MustCompile(`(?i)openai[_\-]?api[_\-]?key[=:]\s*sk-[A-Za-z0-9]{48}`)},
		{"anthropic_api_key", "high", regexp.MustCompile(`(?i)anthropic[_\-]?api[_\-]?key[=:]\s*sk-ant-api03-[A-Za-z0-9\-_]{95}`)},
		{"huggingface_token", "mid", regexp.MustCompile(`(?i)huggingface[_\-]?token[=:]\s*hf_[A-Za-z0-9]{34}`)},
		{"github_token", "high", regexp.MustCompile(`(?i)github[_\-]?token[=:]\s*(ghp|gho|ghu)_[A-Za-z0-9]{36}`)},
		{"slack_token", "mid", regexp.MustCompile(`(?i)slack[_\-]?token[=:]\s*xox[baprs]-[A-Za-z0-9\-]{12,}`)},
		{"twilio_api_key", "mid", regexp.MustCompile(`(?i)twilio[_\-]?api[_\-]?key[=:]\s*[A-Za-z0-9]{32}`)},
		{"mailgun_key", "mid", regexp.MustCompile(`(?i)mailgun[_\-]?api[_\-]?key[=:]\s*[A-Za-z0-9\-]{68}`)},
		{"sendgrid_key", "mid", regexp.MustCompile(`(?i)sendgrid[_\-]?api[_\-]?key[=:]\s*SG\.[A-Za-z0-9\-_.]{68}`)},
		{"stripe_key", "high", regexp.MustCompile(`(?i)stripe[_\-]?(?:api[_-]?key|secret[_-]?key)[=:]\s*(sk|pk)_[a-zA-Z0-9]{24,}`)},
		{"docker_auth", "mid", regexp.MustCompile(`(?i)docker[_\-]?auth[=:]\s*["']?([A-Za-z0-9+/]{22,})["']?`)},
		{"kubernetes_token", "high", regexp.MustCompile(`(?i)kubernetes[_\-]?token[=:]\s*([A-Za-z0-9\-_.]{26,})`)},
		{"npm_token", "mid", regexp.MustCompile(`(?i)npm[_\-]?token[=:]\s*[_-]?npm_[A-Za-z0-9\-]{36}`)},
		{"pypi_token", "mid", regexp.MustCompile(`(?i)pypi[_\-]?token[=:]\s*pypi-[A-Za-z0-9]{34}`)},
	}
}

// redact 脱敏
func redact(val, label string) string {
	switch {
	case strings.HasPrefix(label, "aws_access_key_id"), strings.HasPrefix(label, "github_token"):
		if len(val) >= 8 {
			return val[:4] + "****" + val[len(val)-4:]
		}
	case strings.HasPrefix(label, "aws_secret_access_key"), strings.HasPrefix(label, "azure_storage_key"):
		if len(val) >= 12 {
			return val[:6] + "****" + val[len(val)-6:]
		}
	case strings.HasPrefix(label, "jwt_token"):
		parts := strings.Split(val, ".")
		if len(parts) >= 2 {
			return parts[0] + ".****." + parts[2]
		}
	case strings.HasPrefix(label, "database_uri"):
		if idx := strings.Index(val, "@"); idx != -1 && idx+1 < len(val) {
			return val[:idx+1] + "****"
		}
	default:
		if len(val) > 8 {
			return val[:4] + "****"
		}
	}
	return val
}

// contains 辅助函数
func contains(list []string, item string) bool {
	for _, v := range list {
		if v == item {
			return true
		}
	}
	return false
}
