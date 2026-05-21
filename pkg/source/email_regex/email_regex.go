package email_regex

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/wgpsec/ENScan/pkg/models"
	"github.com/wgpsec/ENScan/pkg/source"
)

// EmailRegex 实现邮箱正则提取
type EmailRegex struct {
	*source.BaseSource
	patterns []*pattern
}

type pattern struct {
	label    string
	severity string
	re       *regexp.Regexp
}

// NewEmailRegex 创建 EmailRegex
func NewEmailRegex() *EmailRegex {
	e := &EmailRegex{
		BaseSource: source.NewBaseSource("email_regex"),
		patterns:   buildPatterns(),
	}
	return e
}

// Name 返回名称
func (e *EmailRegex) Name() string {
	return e.BaseSource.Name()
}

// Accepts 接受的输入类型
func (e *EmailRegex) Accepts() []string {
	return []string{"domain", "company", "url", "text"}
}

// NeedsKey 是否需要 API Key
func (e *EmailRegex) NeedsKey() bool {
	return false
}

// SetConfig 设置配置
func (e *EmailRegex) SetConfig(cfg map[string]any) error {
	_ = e.BaseSource.SetConfig(cfg)
	return nil
}

// Search 执行搜索
func (e *EmailRegex) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	cfg := &source.SearchConfig{
		MaxAssets: 200,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	// 输入：cfg.Extra["texts"] 由上游 pipeline 注入；或把 target 当作 raw 文本
	var texts []string
	if cfg.Extra != nil {
		if v, ok := cfg.Extra["texts"].([]string); ok {
			texts = append(texts, v...)
		} else if v, ok := cfg.Extra["texts"].([]any); ok {
			for _, x := range v {
				if s, ok2 := x.(string); ok2 {
					texts = append(texts, s)
				}
			}
		}
	}
	if strings.Contains(target, "@") || len(target) > 32 {
		// 看起来是一段含邮箱的文本
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
			for _, pat := range e.patterns {
				if len(cfg.EnableTypes) > 0 && !contains(cfg.EnableTypes, pat.label) {
					continue
				}
				if contains(cfg.DisableTypes, pat.label) {
					continue
				}
				for _, m := range pat.re.FindAllString(text, -1) {
					redacted := redactEmail(m, pat.label)
					asset := models.NewAsset().
						WithTitle(fmt.Sprintf("[%s] %s", pat.label, redacted)).
						WithSource(e.Name()).
						WithTags("email", pat.label, "severity:"+pat.severity).
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

// buildPatterns 构建正则模式
func buildPatterns() []*pattern {
	return []*pattern{
		{"general", "mid", regexp.MustCompile(`(?i)[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,24}`)},
		{"support", "mid", regexp.MustCompile(`(?i)(?:support|help|service|tech|技术支持|客服|服务)\s*[:：]?\s*([a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,24})`)},
		{"hr", "mid", regexp.MustCompile(`(?i)(?:hr|人力资源|人事|招聘|recruit)\s*[:：]?\s*([a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,24})`)},
		{"sales", "mid", regexp.MustCompile(`(?i)(?:sales|销售|商务|business)\s*[:：]?\s*([a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,24})`)},
		{"admin", "mid", regexp.MustCompile(`(?i)(?:admin|管理员|root|webmaster)\s*[:：]?\s*([a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,24})`)},
		{"security", "mid", regexp.MustCompile(`(?i)(?:security|安全|sec|cert|证书|ssl|tls)\s*[:：]?\s*([a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,24})`)},
		{"finance", "mid", regexp.MustCompile(`(?i)(?:finance|财务|accounting|财务部|会计)\s*[:：]?\s*([a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,24})`)},
		{"legal", "mid", regexp.MustCompile(`(?i)(?:legal|法务|法务部|合规|compliance)\s*[:：]?\s*([a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,24})`)},
		{"pr", "mid", regexp.MustCompile(`(?i)(?:pr|公关|媒体|press|media)\s*[:：]?\s*([a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,24})`)},
		{"dev", "mid", regexp.MustCompile(`(?i)(?:dev|开发|developer|研发|技术)\s*[:：]?\s*([a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,24})`)},
	}
}

// redactEmail 邮箱脱敏
func redactEmail(val, label string) string {
	if label == "general" {
		// 保留域名，脱敏用户名
		parts := strings.Split(val, "@")
		if len(parts) == 2 {
			user := parts[0]
			domain := parts[1]
			if len(user) > 3 {
				user = user[:2] + "***"
			}
			return user + "@" + domain
		}
	}
	// 其他类型：保留前 2 位
	if len(val) > 6 {
		return val[:2] + "****"
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
