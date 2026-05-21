package pii_scan

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/wgpsec/ENScan/pkg/models"
	"github.com/wgpsec/ENScan/pkg/source"
)

// PIIScan 实现 PII（个人敏感信息）扫描
type PIIScan struct {
	*source.BaseSource
	patterns []*piiPattern
}

type piiPattern struct {
	label    string
	severity string
	re       *regexp.Regexp
	validate func(string) bool // 可选校验函数
}

// NewPIIScan 创建 PIIScan
func NewPIIScan() *PIIScan {
	s := &PIIScan{
		BaseSource: source.NewBaseSource("pii_scan"),
		patterns:   buildPIIPatterns(),
	}
	return s
}

// Name 返回名称
func (s *PIIScan) Name() string {
	return s.BaseSource.Name()
}

// Accepts 接受的输入类型
func (s *PIIScan) Accepts() []string {
	return []string{"domain", "company", "ip", "url"}
}

// NeedsKey 是否需要 API Key
func (s *PIIScan) NeedsKey() bool {
	return false
}

// SetConfig 设置配置
func (s *PIIScan) SetConfig(cfg map[string]any) error {
	_ = s.BaseSource.SetConfig(cfg)
	return nil
}

// Search 执行搜索
func (s *PIIScan) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	cfg := &source.SearchConfig{
		MaxAssets: 500,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	// 模拟从已有资产获取 raw 内容
	texts := []string{
		"手机号 13800138000，身份证 110101199001011234，邮箱 alice@example.com",
		"银行卡 6222021234567890123，MAC 00:1A:2B:3C:4D:5E，内网IP 192.168.1.1",
		"QQ 123456789，微信 wxid_example，车牌 京A12345",
	}
	var allAssets []*models.Asset
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, txt := range texts {
		wg.Add(1)
		go func(text string) {
			defer wg.Done()
			for _, pat := range s.patterns {
				if len(cfg.EnableTypes) > 0 && !contains(cfg.EnableTypes, pat.label) {
					continue
				}
				if contains(cfg.DisableTypes, pat.label) {
					continue
				}
				for _, m := range pat.re.FindAllString(text, -1) {
					if pat.validate != nil && !pat.validate(m) {
						continue
					}
					redacted := redactPII(m, pat.label)
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

// buildPIIPatterns 构建正则模式（从 Python 版移植）
func buildPIIPatterns() []*piiPattern {
	return []*piiPattern{
		{"phone_cn", "high", regexp.MustCompile(`\b1[3-9]\d{9}\b`), nil},
		{"idcard_cn_18", "high", regexp.MustCompile(`\b\d{17}[\dXx]\b`), nil},
		{"idcard_cn_15", "high", regexp.MustCompile(`\b\d{15}\b`), nil},
		{"bankcard_luhn", "high", regexp.MustCompile(`\b\d{13,19}\b`), validateLuhn},
		{"email", "mid", regexp.MustCompile(`[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}`), nil},
		{"vehicle_plate_cn", "mid", regexp.MustCompile(`(?i)[京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤青藏川宁琼使领][A-Z][A-Z0-9]{4,5}[A-Z0-9挂学警港澳]`), nil},
		{"passport_cn", "high", regexp.MustCompile(`(?i)[GEP][A-Z0-9]{8}`), nil},
		{"mac", "mid", regexp.MustCompile(`(?i)(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}`), nil},
		{"ipv4_private", "mid", regexp.MustCompile(`\b(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)\d{1,3}\.\d{1,3}\b`), nil},
		{"qq", "mid", regexp.MustCompile(`(?i)(?:qq[\s号:：]{0,3}|qq[_-]?(?:no|number))[\"'\x60\s:=]+([1-9]\d{4,11})`), nil},
		{"wechat", "mid", regexp.MustCompile(`(?i)(?:wechat|微信|wx[_-]id)[\"'\x60\s:=号：]+([a-zA-Z][a-zA-Z0-9_\-]{5,19})`), nil},
		{"social_credit_code_cn", "high", regexp.MustCompile(`[0-9A-HJ-NPQRTUWXY]{2}\d{6}[0-9A-HJ-NPQRTUWXY]{10}`), nil},
		{"us_ssn", "high", regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`), nil},
		{"iban", "high", regexp.MustCompile(`\b[A-Z]{2}\d{2}(?:[A-Z0-9]{4}\d{7}(?:[A-Z0-9]?){0,16}|[A-Z0-9]{4}\d{14})\b`), nil},
	}
}

// validateLuhn Luhn 校验（银行卡）
func validateLuhn(num string) bool {
	var sum int
	alternate := false
	for i := len(num) - 1; i >= 0; i-- {
		digit := int(num[i] - '0')
		if alternate {
			digit *= 2
			if digit > 9 {
				digit = (digit % 10) + 1
			}
		}
		sum += digit
		alternate = !alternate
	}
	return sum%10 == 0
}

// redactPII 脱敏
func redactPII(val, label string) string {
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
	case label == "mac":
		parts := strings.Split(val, ":")
		if len(parts) == 6 {
			return strings.Join(parts[:3], ":") + ":**:**"
		}
	case label == "ipv4_private":
		parts := strings.Split(val, ".")
		if len(parts) == 4 {
			return parts[0] + "." + parts[1] + ".**.**"
		}
	case label == "qq":
		if len(val) > 4 {
			return val[:2] + "***"
		}
	case label == "wechat":
		if len(val) > 4 {
			return val[:2] + "***"
		}
	case label == "social_credit_code_cn":
		if len(val) == 18 {
			return val[:6] + "********" + val[len(val)-4:]
		}
	case label == "us_ssn":
		return val[:3] + "-**-****"
	case label == "iban":
		if len(val) > 8 {
			return val[:4] + "****" + val[len(val)-4:]
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
