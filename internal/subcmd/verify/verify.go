// Package verify 提供 Ghost verify-engines 子命令
package verify

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/wgpsec/ENScan/pkg/engine/fofa"
	"github.com/wgpsec/ENScan/pkg/engine/hunter"
	"github.com/wgpsec/ENScan/pkg/engine/quake"
	"github.com/wgpsec/ENScan/pkg/engine/shodan"
	"github.com/wgpsec/ENScan/pkg/engine/zerozone"
	"github.com/wgpsec/ENScan/pkg/engine/zoomeye"
)

const fakeKey = "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"

// New 返回 cobra 子命令
func New() *cobra.Command {
	return &cobra.Command{
		Use:   "verify-engines",
		Short: "验证 6 个引擎是否正确发送 API key（用假 key 触发服务端鉴权错误）",
		RunE: func(_ *cobra.Command, _ []string) error {
			fmt.Println("===== 引擎 API Key 鉴权验证（使用假 key） =====")
			fmt.Println()

			run("fofa", func(ctx context.Context) error {
				f := fofa.NewFOFA()
				f.SetKey(fakeKey)
				_, err := f.Search(ctx, "domain=example.com")
				return err
			})
			run("hunter", func(ctx context.Context) error {
				h := hunter.NewHunter()
				h.SetKey(fakeKey)
				_, err := h.Search(ctx, `domain.suffix="example.com"`)
				return err
			})
			run("quake", func(ctx context.Context) error {
				q := quake.NewQuake()
				q.SetKey(fakeKey)
				_, err := q.Search(ctx, "domain:example.com")
				return err
			})
			run("shodan", func(ctx context.Context) error {
				s := shodan.NewShodan()
				s.SetKey(fakeKey)
				_, err := s.Search(ctx, "hostname:example.com")
				return err
			})
			run("zerozone", func(ctx context.Context) error {
				z := zerozone.NewZeroZone()
				z.SetKey(fakeKey)
				_, err := z.Search(ctx, "example.com")
				return err
			})
			run("zoomeye", func(ctx context.Context) error {
				z := zoomeye.NewZoomEye()
				z.SetKey(fakeKey)
				_, err := z.Search(ctx, "site:example.com")
				return err
			})

			fmt.Println()
			fmt.Println("===== 各引擎 key 注入位置（源码确认） =====")
			fmt.Println("  fofa     : URL  ?key=<KEY>&qbase64=...               (query)")
			fmt.Println("  hunter   : URL  ?api-key=<KEY>&query=...             (query)")
			fmt.Println("  quake    : HEAD X-QuakeToken: <KEY>                  (header)")
			fmt.Println("  shodan   : URL  ?key=<KEY>&query=...                 (query)")
			fmt.Println("  zerozone : URL  ?key=<KEY>&query=...                 (query)")
			fmt.Println("  zoomeye  : HEAD API-KEY: <KEY>                       (header)")
			fmt.Println()
			uu, _ := url.Parse("https://fofa.info/api/v1/search/all")
			q := uu.Query()
			q.Set("key", fakeKey)
			q.Set("qbase64", "ZG9tYWluPWV4YW1wbGUuY29t")
			q.Set("size", "10")
			uu.RawQuery = q.Encode()
			fmt.Println("FOFA 样例 URL:", uu.String())
			return nil
		},
	}
}

func run(name string, fn func(ctx context.Context) error) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	start := time.Now()
	err := fn(ctx)
	dur := time.Since(start)
	status := "?"
	hint := ""
	if err == nil {
		status = "OK"
		hint = "(意外成功，假 key 不应通过)"
	} else {
		msg := err.Error()
		low := strings.ToLower(msg)
		switch {
		case strings.Contains(msg, "无效") || strings.Contains(msg, "过期") || strings.Contains(msg, "错误") ||
			strings.Contains(msg, "禁止") || strings.Contains(low, "invalid") || strings.Contains(low, "401") ||
			strings.Contains(low, "403") || strings.Contains(low, "unauthorized") || strings.Contains(low, "forbidden") ||
			strings.Contains(low, "key error") || strings.Contains(low, "incorrect") || strings.Contains(low, "wrong") ||
			strings.Contains(low, "expired"):
			status = "✅ KEY 已发送"
			hint = "(服务端识别 key 但拒绝)"
		case strings.Contains(low, "eof") && strings.Contains(low, "key="):
			status = "✅ KEY 已发送"
			hint = "(URL 含 key，服务端断连)"
		case strings.Contains(low, "missing") || strings.Contains(low, "缺失") || strings.Contains(low, "缺少") ||
			strings.Contains(low, "no key") || strings.Contains(low, "未提供"):
			status = "❌ KEY 未发送"
			hint = "(服务端报告缺少 key)"
		case strings.Contains(low, "timeout") || strings.Contains(low, "deadline") ||
			strings.Contains(low, "no such host") || strings.Contains(low, "dial tcp") || strings.Contains(low, "tls"):
			status = "⚠️ 网络不可达"
			hint = "(无法验证)"
		default:
			status = "? 未知"
			hint = msg
		}
		if len(hint) > 120 {
			hint = hint[:120] + "..."
		}
	}
	fmt.Printf("[%-8s] %-15s  %-6s  %s\n", name, dur.Truncate(time.Millisecond), status, hint)
}
