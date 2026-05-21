// Package smoke 提供 Ghost smoke 子命令：全量数据源冒烟测试
package smoke

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/spf13/cobra"

	"github.com/wgpsec/ENScan/pkg/registry"
	"github.com/wgpsec/ENScan/pkg/source"
)

type result struct {
	name     string
	target   string
	accepts  []string
	category string
	detail   string
	count    int
	dur      time.Duration
}

// New 返回 cobra 子命令
func New() *cobra.Command {
	var proxy, only string
	var timeout time.Duration

	cmd := &cobra.Command{
		Use:   "smoke",
		Short: "全量数据源冒烟测试（按 Accepts 选目标，按错误归档）",
		RunE: func(_ *cobra.Command, _ []string) error {
			runSmoke(proxy, only, timeout)
			return nil
		},
	}
	cmd.Flags().StringVar(&proxy, "proxy", "", "HTTP/HTTPS proxy URL (e.g. http://127.0.0.1:7897)")
	cmd.Flags().DurationVar(&timeout, "timeout", 15*time.Second, "per-source request timeout")
	cmd.Flags().StringVar(&only, "only", "", "comma-separated source names to test (empty=all)")
	return cmd
}

func runSmoke(proxy, only string, timeout time.Duration) {
	if proxy != "" {
		_ = os.Setenv("HTTPS_PROXY", proxy)
		_ = os.Setenv("HTTP_PROXY", proxy)
		_ = os.Setenv("ALL_PROXY", proxy)
		const np = "localhost,127.0.0.1,.cn,beianx.cn,bdziyi.com,chinaz.com,fofa.info,fofa.so,hunter.qianxin.com,quake.360.net,zoomeye.org,zoomeye.hk,0.zone,0zone.ai,gitee.com,gitee.io,tencent.com,qq.com,aliyun.com,aliyuncs.com,huaweicloud.com,baidu.com,bytedance.com,tianyancha.com,qcc.com,qichacha.com"
		_ = os.Setenv("NO_PROXY", np)
		_ = os.Setenv("no_proxy", np)
	}
	onlySet := map[string]struct{}{}
	if only != "" {
		for _, n := range strings.Split(only, ",") {
			n = strings.TrimSpace(n)
			if n != "" {
				onlySet[n] = struct{}{}
			}
		}
	}

	all := registry.AllSources()
	if timeout > 0 {
		merged := map[string]any{"timeout": int(timeout.Seconds())}
		for _, s := range all {
			_ = s.SetConfig(merged)
		}
	}
	names := make([]string, 0, len(all))
	for n := range all {
		names = append(names, n)
	}
	sort.Strings(names)

	results := make([]result, 0, len(names))
	var mu sync.Mutex
	var done atomic.Int32
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup

	for _, name := range names {
		if len(onlySet) > 0 {
			if _, ok := onlySet[name]; !ok {
				continue
			}
		}
		src := all[name]
		accepts := src.Accepts()
		target := chooseTarget(accepts)

		wg.Add(1)
		sem <- struct{}{}
		go func(name, target string, accepts []string, src source.Source) {
			defer wg.Done()
			defer func() { <-sem }()

			r := result{name: name, target: target, accepts: accepts}
			defer func() {
				if rec := recover(); rec != nil {
					r.category = "panic"
					r.detail = fmt.Sprintf("panic: %v", rec)
				}
				mu.Lock()
				results = append(results, r)
				mu.Unlock()
				n := done.Add(1)
				if int(n)%10 == 0 {
					fmt.Printf("  ... %d/%d\n", n, len(names))
				}
			}()

			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			start := time.Now()
			assets, err := src.Search(ctx, target)
			r.dur = time.Since(start)
			r.count = len(assets)
			if err == nil {
				if len(assets) == 0 {
					r.category = "empty"
					r.detail = "no match"
				} else {
					r.category = "ok"
					r.detail = fmt.Sprintf("%d assets", len(assets))
				}
			} else {
				r.category, r.detail = categorize(err, len(assets))
			}
		}(name, target, accepts, src)
	}
	wg.Wait()

	byCat := map[string][]result{}
	for _, r := range results {
		byCat[r.category] = append(byCat[r.category], r)
	}
	cats := []string{"panic", "ok", "empty", "auth_required", "timeout", "dns_or_dial", "http_status", "parse_error", "other"}
	fmt.Println()
	fmt.Println("===== 冒烟测试汇总 =====")
	for _, c := range cats {
		fmt.Printf("[%s] %d 个:\n", c, len(byCat[c]))
		sort.Slice(byCat[c], func(i, j int) bool { return byCat[c][i].name < byCat[c][j].name })
		for _, r := range byCat[c] {
			detail := r.detail
			if len(detail) > 100 {
				detail = detail[:100] + "..."
			}
			fmt.Printf("  - %-26s [%s] -> %s\n", r.name, r.target, detail)
		}
		fmt.Println()
	}

	if len(byCat["panic"]) > 0 || len(byCat["other"]) > 0 {
		fmt.Println("⚠️ 存在 panic 或未知错误，需要排查")
	} else {
		fmt.Println("✅ 无 panic / 未知错误")
	}
}

func categorize(err error, _ int) (string, string) {
	if err == nil {
		return "ok", ""
	}
	msg := err.Error()
	low := strings.ToLower(msg)
	switch {
	case strings.Contains(low, "panic"):
		return "panic", msg
	case strings.Contains(low, "context deadline") || strings.Contains(low, "timeout") || strings.Contains(low, "client.timeout"):
		return "timeout", "network timeout"
	case strings.Contains(low, "no such host") || strings.Contains(low, "dial tcp"):
		return "dns_or_dial", msg
	case strings.Contains(low, "401") || strings.Contains(low, "403") || strings.Contains(low, "unauthorized") ||
		strings.Contains(low, "forbidden") || strings.Contains(low, "needs key") || strings.Contains(low, "needs fofa_key") ||
		strings.Contains(low, "needs quake_key") || strings.Contains(low, "needs key and target") ||
		strings.Contains(low, "api key") || strings.Contains(low, "api error") || strings.Contains(low, "eof") ||
		strings.Contains(msg, "账号") || strings.Contains(msg, "令牌"):
		return "auth_required", msg
	case strings.Contains(low, "status 4") || strings.Contains(low, "status 5"):
		return "http_status", msg
	case strings.Contains(low, "invalid json") || strings.Contains(low, "unmarshal"):
		return "parse_error", msg
	default:
		return "other", msg
	}
}

func chooseTarget(accepts []string) string {
	prefer := map[string]string{
		"domain":  "example.com",
		"ip":      "8.8.8.8",
		"url":     "https://example.com",
		"email":   "test@example.com",
		"hash":    "44d88612fea8a8f36de82e1278abb02f",
		"keyword": "example",
		"company": "Example Inc",
	}
	for _, t := range accepts {
		if v, ok := prefer[t]; ok {
			return v
		}
	}
	return "example.com"
}
