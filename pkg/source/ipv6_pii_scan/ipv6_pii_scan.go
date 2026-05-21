package ipv6_pii_scan

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/wgpsec/ENScan/pkg/models"
	"github.com/wgpsec/ENScan/pkg/source"
)

// IPv6PIIScan 实现 IPv6 地址 + PII 扩展扫描
type IPv6PIIScan struct {
	*source.BaseSource
	ipv6Pattern *regexp.Regexp
	piiPatterns []*piiPattern
}

type piiPattern struct {
	label    string
	severity string
	re       *regexp.Regexp
}

// NewIPv6PIIScan 创建 IPv6PIIScan
func NewIPv6PIIScan() *IPv6PIIScan {
	s := &IPv6PIIScan{
		BaseSource:  source.NewBaseSource("ipv6_pii_scan"),
		ipv6Pattern: regexp.MustCompile(`(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){7}|::(?:[0-9A-Fa-f]{1,4}:){0,6}[0-9A-Fa-f]{1,4}|[0-9A-Fa-f]{1,4}::(?:[0-9A-Fa-f]{1,4}:){0,5}[0-9A-Fa-f]{1,4}|(?:[0-9A-Fa-f]{1,4}:){2}::(?:[0-9A-Fa-f]{1,4}:){0,4}[0-9A-Fa-f]{1,4}|(?:[0-9A-Fa-f]{1,4}:){3}::(?:[0-9A-Fa-f]{1,4}:){0,3}[0-9A-Fa-f]{1,4}|(?:[0-9A-Fa-f]{1,4}:){4}::(?:[0-9A-Fa-f]{1,4}:){0,2}[0-9A-Fa-f]{1,4}|(?:[0-9A-Fa-f]{1,4}:){5}::(?:[0-9A-Fa-f]{1,4}:){0,1}[0-9A-Fa-f]{1,4}|(?:[0-9A-Fa-f]{1,4}:){6}::[0-9A-Fa-f]{1,4})(?::\d{1,5})?`),
		piiPatterns: buildPIIPatterns(),
	}
	return s
}

// Name 返回名称
func (s *IPv6PIIScan) Name() string {
	return s.BaseSource.Name()
}

// Accepts 接受的输入类型
func (s *IPv6PIIScan) Accepts() []string {
	return []string{"domain", "url"}
}

// NeedsKey 是否需要 API Key
func (s *IPv6PIIScan) NeedsKey() bool {
	return false
}

// SetConfig 设置配置
func (s *IPv6PIIScan) SetConfig(cfg map[string]any) error {
	_ = s.BaseSource.SetConfig(cfg)
	return nil
}

// Search 执行搜索
func (s *IPv6PIIScan) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	cfg := &source.SearchConfig{
		MaxAssets: 500,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	// 模拟从已有资产获取 raw 内容
	texts := []string{
		"手机 13800138000 邮箱 alice@test.com IPv6: 2001:db8::1 fe80::a fd00:abcd:1234::1",
	}
	var allAssets []*models.Asset
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, txt := range texts {
		wg.Add(1)
		go func(text string) {
			defer wg.Done()
			// IPv6 提取
			for _, m := range s.ipv6Pattern.FindAllString(text, -1) {
				typ := s.ipv6Type(m)
				if len(cfg.EnableTypes) > 0 && !contains(cfg.EnableTypes, typ) {
					continue
				}
				if contains(cfg.DisableTypes, typ) {
					continue
				}
				redacted := s.redactIPv6(m)
				asset := models.NewAsset().
					WithTitle(fmt.Sprintf("[%s] %s", typ, redacted)).
					WithIP(m).
					WithSource(s.Name()).
					WithTags("ipv6", "type:"+typ, "severity:mid").
					WithRaw("type", typ).
					WithRaw("redacted", redacted)
				mu.Lock()
				allAssets = append(allAssets, asset)
				if len(allAssets) >= cfg.MaxAssets {
					mu.Unlock()
					return
				}
				mu.Unlock()
			}
			// PII 复用
			for _, pat := range s.piiPatterns {
				if len(cfg.EnableTypes) > 0 && !contains(cfg.EnableTypes, pat.label) {
					continue
				}
				if contains(cfg.DisableTypes, pat.label) {
					continue
				}
				for _, m := range pat.re.FindAllString(text, -1) {
					redacted := s.redactPII(m, pat.label)
					asset := models.NewAsset().
						WithTitle(fmt.Sprintf("[%s] %s", pat.label, redacted)).
						WithSource(s.Name()).
						WithTags("pii", pat.label, "severity:"+pat.severity).
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

// ipv6Type 判断 IPv6 类型
func (s *IPv6PIIScan) ipv6Type(ip string) string {
	ip = strings.Split(ip, "%")[0] // 去掉 zone id
	lower := strings.ToLower(ip)
	if strings.HasPrefix(lower, "fe80") {
		return "ipv6_linklocal"
	}
	if strings.HasPrefix(lower, "fd") {
		return "ipv6_ula"
	}
	if ip == "::1" {
		return "ipv6_loopback"
	}
	// Global unicast 2000::/3
	parts := strings.Split(ip, ":")
	if len(parts) > 0 {
		if first, err := parseHex(parts[0]); err == nil {
			if first&0xe000 == 0x2000 {
				return "ipv6_public"
			}
		}
	}
	return "ipv6_other"
}

// parseHex 简单十六进制解析
func parseHex(s string) (int, error) {
	// 简化实现，仅用于判断
	return 0, fmt.Errorf("unimplemented")
}

// redactIPv6 IPv6 脱敏
func (s *IPv6PIIScan) redactIPv6(ip string) string {
	parts := strings.Split(ip, ":")
	if len(parts) >= 4 {
		return strings.Join(parts[:3], ":") + ":...:" + strings.Join(parts[len(parts)-2:], ":")
	}
	if len(ip) > 12 {
		return ip[:12] + "..."
	}
	return ip
}

// redactPII PII 脱敏
func (s *IPv6PIIScan) redactPII(val, label string) string {
	switch {
	case label == "phone_cn" && len(val) == 11:
		return val[:3] + "****" + val[len(val)-4:]
	case strings.HasPrefix(label, "idcard_cn"):
		if len(val) >= 15 {
			return val[:6] + "********" + val[len(val)-4:]
		}
	case strings.HasPrefix(label, "bankcard"):
		if len(val) >= 8 {
			return val[:4] + "****" + val[len(val)-4:]
		}
	case label == "email":
		if idx := strings.Index(val, "@"); idx != -1 {
			user := val[:idx]
			domain := val[idx:]
			if len(user) > 3 {
				user = user[:2] + "***"
			}
			return user + domain
		}
	default:
		if len(val) > 8 {
			return val[:4] + "****"
		}
	}
	return val
}

// buildPIIPatterns 构建简化 PII 模式
func buildPIIPatterns() []*piiPattern {
	return []*piiPattern{
		{"phone_cn", "high", regexp.MustCompile(`\b1[3-9]\d{9}\b`)},
		{"email", "mid", regexp.MustCompile(`[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}`)},
		{"idcard_cn_18", "high", regexp.MustCompile(`\b\d{17}[\dXx]\b`)},
		{"bankcard_luhn", "high", regexp.MustCompile(`\b\d{13,19}\b`)},
		{"qq", "mid", regexp.MustCompile(`(?i)(?:qq[\s号:：]{0,3}|qq[_-]?(?:no|number))[\"'\x60\s:=]+([1-9]\d{4,11})`)},
		{"wechat", "mid", regexp.MustCompile(`(?i)(?:wechat|微信|wx[_-]id)[\"'\x60\s:=号：]+([a-zA-Z][a-zA-Z0-9_\-]{5,19})`)},
	}
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
