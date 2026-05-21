package core

import (
	"fmt"
	"regexp"
	"strings"
)

// SupportedEngines 支持的引擎
var SupportedEngines = []string{"fofa", "quake", "hunter", "zoomeye", "shodan", "zerozone"}

// FieldMap DSL 字段 -> 各平台原生字段名
var FieldMap = map[string]map[string]string{
	"fofa": {
		"domain": "domain", "host": "host", "ip": "ip", "port": "port",
		"title": "title", "body": "body", "server": "server", "header": "header",
		"cert": "cert", "icp": "icp", "country": "country", "city": "city",
		"org": "org", "asn": "asn", "app": "app", "product": "app",
		"os": "os", "jarm": "jarm", "favicon": "icon_hash", "service": "protocol",
	},
	"quake": {
		"domain": "domain", "host": "hostname", "ip": "ip", "port": "port",
		"title": "title", "body": "response", "server": "service.http.server",
		"header": "service.response", "cert": "cert", "icp": "icp",
		"country": "country_code", "city": "city", "org": "isp", "asn": "asn",
		"app": "app", "product": "app", "os": "os",
		"jarm": "jarm", "favicon": "icon_hash", "service": "service",
	},
	"shodan": {
		"domain": "domain", "host": "hostname", "ip": "ip", "port": "port",
		"title": "title", "body": "html", "server": "server", "header": "http.title",
		"cert": "ssl", "country": "country", "city": "city", "org": "org",
		"asn": "asn", "app": "product", "product": "product",
		"os": "os", "jarm": "jarm", "favicon": "http.favicon.hash", "service": "product",
	},
	"zoomeye": {
		"domain": "hostname", "host": "hostname", "ip": "ip", "port": "port",
		"title": "title", "body": "banner", "server": "service", "header": "banner",
		"cert": "cert", "country": "country", "city": "city", "org": "org",
		"asn": "asn", "app": "service", "product": "service",
		"os": "os", "jarm": "jarm", "favicon": "favicon", "service": "service",
	},
	"hunter": {
		"domain": "domain", "host": "web.title", "ip": "ip", "port": "port",
		"title": "web.title", "body": "web.body", "server": "web.server",
		"header": "header", "cert": "cert", "country": "country", "city": "city",
		"org": "org", "asn": "asn", "app": "app", "product": "app",
		"os": "os", "jarm": "jarm", "favicon": "web.icon", "service": "protocol",
	},
	"zerozone": {
		"domain": "domain", "host": "host", "ip": "ip", "port": "port",
		"title": "title", "body": "content", "server": "server", "header": "header",
		"cert": "cert", "country": "country", "city": "city", "org": "org",
		"asn": "asn", "app": "app", "product": "app",
		"os": "os", "jarm": "jarm", "favicon": "favicon", "service": "service",
	},
}

// TranslateToNative 将 DSL 翻译为指定引擎的原生语法
func TranslateToNative(dsl, engine string) (string, error) {
	if engine == "" {
		return "", fmt.Errorf("engine required")
	}
	fm, ok := FieldMap[engine]
	if !ok {
		return "", fmt.Errorf("unsupported engine: %s", engine)
	}
	// 简单正则替换 DSL 字段
	// 例：domain="example.com" -> domain="example.com"
	// 对于字段名不一致的平台，替换字段名
	for dslField, nativeField := range fm {
		if dslField == nativeField {
			continue
		}
		re := regexp.MustCompile(fmt.Sprintf(`\b%s\b=`, dslField))
		dsl = re.ReplaceAllString(dsl, nativeField+"=")
	}
	// 处理平台独家字段透传（如 fofa::is_honeypot="true"）
	// 这里直接保留，不处理
	return dsl, nil
}

// TranslateAll 把 DSL 翻译到全部 SupportedEngines，返回 engine→native 的映射。
// 翻译失败的引擎会写入 errs 而不是 out（与 Python translate_all 等价）。
func TranslateAll(dsl string) (out map[string]string, errs map[string]error) {
	out = make(map[string]string, len(SupportedEngines))
	errs = make(map[string]error)
	for _, eng := range SupportedEngines {
		s, err := TranslateToNative(dsl, eng)
		if err != nil {
			errs[eng] = err
			continue
		}
		out[eng] = s
	}
	return out, errs
}

// ParseNative 将原生语句反解析为 DSL（简化实现）
func ParseNative(native, engine string) (string, error) {
	if engine == "" {
		return "", fmt.Errorf("engine required")
	}
	fm, ok := FieldMap[engine]
	if !ok {
		return "", fmt.Errorf("unsupported engine: %s", engine)
	}
	// 反向替换原生字段为 DSL 字段
	for dslField, nativeField := range fm {
		if dslField == nativeField {
			continue
		}
		re := regexp.MustCompile(fmt.Sprintf(`\b%s\b=`, nativeField))
		native = re.ReplaceAllString(native, dslField+"=")
	}
	return native, nil
}

// ValidateDSL 验证 DSL 语法（简单检查）
func ValidateDSL(dsl string) error {
	// 检查是否包含未闭合引号
	if strings.Count(dsl, `"`)%2 != 0 {
		return fmt.Errorf("unclosed quotes")
	}
	// 检查是否包含不支持的运算符
	if strings.Contains(dsl, "&&") || strings.Contains(dsl, "||") {
		// 允许
	}
	return nil
}

// ExtractEngineExclusiveFields 提取平台独家字段
func ExtractEngineExclusiveFields(dsl string) map[string]map[string]string {
	out := make(map[string]map[string]string)
	// 正则匹配 engine::field="value"
	re := regexp.MustCompile(`(\w+)::(\w+)="([^"]*)"`)
	matches := re.FindAllStringSubmatch(dsl, -1)
	for _, m := range matches {
		if len(m) == 4 {
			engine, field, value := m[1], m[2], m[3]
			if _, ok := out[engine]; !ok {
				out[engine] = make(map[string]string)
			}
			out[engine][field] = value
		}
	}
	return out
}

// StripEngineExclusiveFields 移除平台独家字段，返回通用 DSL
func StripEngineExclusiveFields(dsl string) string {
	re := regexp.MustCompile(`\w+::\w+="[^"]*"\s*`)
	return re.ReplaceAllString(dsl, "")
}
