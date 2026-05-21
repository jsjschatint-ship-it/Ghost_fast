// Package jscrawl is the `ghost jscrawl` subcommand: recursive HTML/JS crawler
// + endpoint + secret extraction.
package jscrawl

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/wgpsec/ENScan/pkg/active/jscrawl"
)

type flags struct {
	urls            []string
	urlsFile        string
	useStdin        bool
	maxDepth        int
	maxPages        int
	concurrency     int
	timeoutSec      int
	maxBodyMB       int
	sameHostOnly    bool
	allowExternalJS bool
	followRedirects bool
	userAgent       string
	outputPath      string
	format          string
}

// New constructs the cobra command.
func New() *cobra.Command {
	f := &flags{
		sameHostOnly:    true,
		followRedirects: true,
	}
	cmd := &cobra.Command{
		Use:   "jscrawl",
		Short: "递归爬 HTML/JS：提取 API 端点 + 暴露的密钥/凭证",
		Long: `ghost jscrawl 递归抓取 HTML 页面和 JS 文件，从中提炼：

  • API 端点：/api/* /v1/* /graphql 等绝对路径，以及完整 URL
  • 暴露密钥：AWS / 阿里云 / Google API key、GitHub / GitLab / Slack token、
    JWT、Stripe live key、私钥块、Slack webhook、source map URL 等 20+ 规则

工作流：
  HTML 种子页 → 提取 <script src> + 同源 <a href> + modulepreload
            → 抓取每个 JS 文件 → 在正文里再找 ".js" 字符串递归
            → 命中规则去重聚合输出

输入：
  -u / --url       种子 URL（可重复）
  -U / --url-file  URL 文件（一行一个）
  --stdin          从 stdin 读 URL`,
		RunE: f.run,
	}
	cmd.Flags().StringSliceVarP(&f.urls, "url", "u", nil, "种子 URL（可重复，或逗号分隔）")
	cmd.Flags().StringVarP(&f.urlsFile, "url-file", "U", "", "URL 文件，一行一个")
	cmd.Flags().BoolVar(&f.useStdin, "stdin", false, "从 stdin 读 URL")
	cmd.Flags().IntVar(&f.maxDepth, "depth", 2, "最大递归深度（0=只爬种子）")
	cmd.Flags().IntVar(&f.maxPages, "max-pages", 200, "总抓取上限（HTML+JS 合计）")
	cmd.Flags().IntVar(&f.concurrency, "concurrency", 8, "并发数")
	cmd.Flags().IntVar(&f.timeoutSec, "timeout", 12, "单次 HTTP 超时（秒）")
	cmd.Flags().IntVar(&f.maxBodyMB, "max-body-mb", 5, "单文件最大扫描字节（MB）")
	cmd.Flags().BoolVar(&f.sameHostOnly, "same-host-only", true, "只跟同源链接（默认 true）")
	cmd.Flags().BoolVar(&f.allowExternalJS, "allow-external-js", false, "同源限制下也允许跨域 .js")
	cmd.Flags().BoolVar(&f.followRedirects, "follow-redirects", true, "跟随 3xx")
	cmd.Flags().StringVar(&f.userAgent, "user-agent", "", "自定义 User-Agent")
	cmd.Flags().StringVarP(&f.outputPath, "output", "o", "", "输出文件（默认 stdout）")
	cmd.Flags().StringVar(&f.format, "format", "json", "输出格式：json|jsonl|text")
	return cmd
}

func (f *flags) run(cmd *cobra.Command, args []string) error {
	seeds, err := f.collectURLs()
	if err != nil {
		return err
	}
	if len(seeds) == 0 {
		return fmt.Errorf("必须通过 -u / -U / --stdin 提供至少一个种子 URL")
	}

	cfg := jscrawl.Config{
		Seeds:           seeds,
		MaxDepth:        f.maxDepth,
		MaxPages:        f.maxPages,
		Concurrency:     f.concurrency,
		Timeout:         time.Duration(f.timeoutSec) * time.Second,
		MaxBodyBytes:    int64(f.maxBodyMB) * 1024 * 1024,
		SameHostOnly:    f.sameHostOnly,
		AllowExternalJS: f.allowExternalJS,
		FollowRedirects: f.followRedirects,
		UserAgent:       f.userAgent,
	}

	ctx, cancel := context.WithCancel(cmd.Context())
	if ctx == nil {
		ctx, cancel = context.WithCancel(context.Background())
	}
	defer cancel()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() { <-sigCh; cancel() }()

	res := jscrawl.Crawl(ctx, cfg)
	return f.emit(res)
}

// collectURLs merges -u / -U / --stdin, deduplicating.
func (f *flags) collectURLs() ([]string, error) {
	seen := map[string]struct{}{}
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" || strings.HasPrefix(s, "#") {
			return
		}
		if !strings.HasPrefix(s, "http://") && !strings.HasPrefix(s, "https://") {
			s = "https://" + s
		}
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	for _, raw := range f.urls {
		for _, p := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ';' }) {
			add(p)
		}
	}
	if f.urlsFile != "" {
		fh, err := os.Open(f.urlsFile)
		if err != nil {
			return nil, fmt.Errorf("open --url-file: %w", err)
		}
		defer fh.Close()
		sc := bufio.NewScanner(fh)
		sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
		for sc.Scan() {
			add(sc.Text())
		}
		if err := sc.Err(); err != nil {
			return nil, err
		}
	}
	if f.useStdin {
		sc := bufio.NewScanner(os.Stdin)
		sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
		for sc.Scan() {
			add(sc.Text())
		}
		if err := sc.Err(); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// emit serialises results in the requested format.
func (f *flags) emit(res *jscrawl.Result) error {
	w := os.Stdout
	if f.outputPath != "" && f.outputPath != "-" {
		fh, err := os.Create(f.outputPath)
		if err != nil {
			return err
		}
		defer fh.Close()
		w = fh
	}
	switch strings.ToLower(f.format) {
	case "json", "":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(res)
	case "jsonl":
		enc := json.NewEncoder(w)
		for _, p := range res.Pages {
			if err := enc.Encode(p); err != nil {
				return err
			}
		}
		return nil
	case "text":
		fmt.Fprintf(w, "JS Crawl: %d seeds → %d pages (%d JS) / %d endpoints / %d secrets / %dms\n",
			len(res.Seeds), res.Stats.PagesFetched, res.Stats.JSFiles, res.Stats.EndpointsFound, res.Stats.SecretsFound, res.DurationMS)
		if len(res.Endpoints) > 0 {
			fmt.Fprintln(w, "\n=== Endpoints ===")
			for _, e := range res.Endpoints {
				fmt.Fprintln(w, "  ", e)
			}
		}
		if len(res.Secrets) > 0 {
			fmt.Fprintln(w, "\n=== Secrets ===")
			for _, s := range res.Secrets {
				fmt.Fprintf(w, "  [%s] %s = %s\n", s.Severity, s.Rule, s.Value)
			}
		}
		return nil
	default:
		return fmt.Errorf("unknown --format %q", f.format)
	}
}
