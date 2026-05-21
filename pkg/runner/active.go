package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/wgpsec/ENScan/pkg/models"
)

// ActiveScanner 主动模式扫描器（naabu + httpx）
type ActiveScanner struct {
	naabuPath string
	httpxPath string
	proxy     string
	ports     []int
}

// NewActiveScanner 创建主动扫描器
func NewActiveScanner(proxy string, ports []int) *ActiveScanner {
	return &ActiveScanner{
		naabuPath: "naabu", // 假设在 PATH
		httpxPath: "httpx",
		proxy:     proxy,
		ports:     ports,
	}
}

// ScanCIDR 扫描 CIDR（主动模式）
func (a *ActiveScanner) ScanCIDR(ctx context.Context, cidr string) ([]*models.Asset, error) {
	// 1) naabu -cidr X -p 80,443
	aliveIPs, err := a.runNaabu(ctx, cidr)
	if err != nil {
		return nil, fmt.Errorf("naabu: %w", err)
	}
	if len(aliveIPs) == 0 {
		return nil, fmt.Errorf("no alive IPs for %s", cidr)
	}

	// 2) httpx -json 指纹
	var allAssets []*models.Asset
	for _, ipPort := range aliveIPs {
		assets, err := a.runHttpx(ctx, ipPort, cidr)
		if err == nil {
			allAssets = append(allAssets, assets...)
		}
	}
	return allAssets, nil
}

// runNaabu 执行 naabu 扫描
func (a *ActiveScanner) runNaabu(ctx context.Context, cidr string) ([]string, error) {
	args := []string{
		"-cidr", cidr,
		"-p", strings.Join(a.portsToStrings(), ","),
		"-silent",
		"-json",
	}
	if a.proxy != "" {
		args = append(args, "-proxy", a.proxy)
	}
	cmd := exec.CommandContext(ctx, a.naabuPath, args...)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("naabu exec: %w", err)
	}
	var results []string
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		// naabu 输出 JSON，简单解析 ip:port
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			continue
		}
		if host, ok := m["host"].(string); ok {
			if port, ok := m["port"].(float64); ok {
				results = append(results, fmt.Sprintf("%s:%d", host, int(port)))
			}
		}
	}
	return results, nil
}

// runHttpx 执行 httpx 指纹识别
func (a *ActiveScanner) runHttpx(ctx context.Context, ipPort, cidr string) ([]*models.Asset, error) {
	args := []string{
		"-json",
		"-silent",
		"-title",
		"-tech-detect",
		"-status-code",
	}
	if a.proxy != "" {
		args = append(args, "-proxy", a.proxy)
	}
	cmd := exec.CommandContext(ctx, a.httpxPath, append(args, ipPort)...)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("httpx exec: %w", err)
	}
	var assets []*models.Asset
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			continue
		}
		host := getString(m, "host")
		url := getString(m, "url")
		title := getString(m, "title")
		status := getInt(m, "status_code")
		techs := getStrings(m, "technologies")
		asset := models.NewAsset().
			WithTitle(fmt.Sprintf("[Active] %s (%s)", host, title)).
			WithHost(host).
			WithURL(url).
			WithSource("active").
			WithTags("active", "naabu", "httpx").
			WithRaw("cidr", cidr).
			WithRaw("status", strconv.Itoa(status)).
			WithRaw("title", title).
			WithRaw("tech", strings.Join(techs, ","))
		assets = append(assets, asset)
	}
	return assets, nil
}

// portsToStrings 转换端口为字符串切片
func (a *ActiveScanner) portsToStrings() []string {
	var out []string
	for _, p := range a.ports {
		out = append(out, strconv.Itoa(p))
	}
	return out
}

// 辅助函数
func getString(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func getInt(m map[string]any, key string) int {
	if v, ok := m[key].(float64); ok {
		return int(v)
	}
	return 0
}

func getStrings(m map[string]any, key string) []string {
	if v, ok := m[key].([]interface{}); ok {
		var out []string
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}
