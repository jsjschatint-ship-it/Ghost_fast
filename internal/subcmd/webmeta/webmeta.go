package webmeta

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/wgpsec/ENScan/pkg/active/webmeta"
)

type flags struct {
	targets         []string
	targetFile      string
	useStdin        bool
	concurrency     int
	timeoutSec      int
	maxBodyKB       int
	maxSitemapURLs  int
	maxSitemaps     int
	fetchRobots     bool
	fetchSitemap    bool
	followRedirects bool
	tryHTTPFallback bool
	skipTLSVerify   bool
	userAgent       string
	outputPath      string
	format          string
}

func New() *cobra.Command {
	f := &flags{
		fetchRobots:     true,
		fetchSitemap:    true,
		followRedirects: true,
		tryHTTPFallback: true,
	}
	cmd := &cobra.Command{
		Use:   "webmeta",
		Short: "网页元信息 + robots/sitemap 公开 URL 采集",
		Long: `ghost webmeta 采集公开网页元信息：title/meta/OpenGraph/ICP/邮箱/电话，
并解析 robots.txt 与 sitemap.xml 中公开列出的路径和 URL。`,
		RunE: f.run,
	}
	cmd.Flags().StringSliceVarP(&f.targets, "target", "t", nil, "目标 URL / host（可重复，或逗号分隔）")
	cmd.Flags().StringVarP(&f.targetFile, "target-file", "T", "", "目标文件，一行一个")
	cmd.Flags().BoolVar(&f.useStdin, "stdin", false, "从 stdin 读目标")
	cmd.Flags().IntVar(&f.concurrency, "concurrency", 8, "并发数")
	cmd.Flags().IntVar(&f.timeoutSec, "timeout", 10, "单次 HTTP 超时（秒）")
	cmd.Flags().IntVar(&f.maxBodyKB, "max-body-kb", 512, "单响应最多读取 KB")
	cmd.Flags().IntVar(&f.maxSitemapURLs, "max-sitemap-urls", 200, "最多保留 sitemap URL 数")
	cmd.Flags().IntVar(&f.maxSitemaps, "max-sitemaps", 5, "最多读取 sitemap 文件数")
	cmd.Flags().BoolVar(&f.fetchRobots, "robots", true, "读取 robots.txt")
	cmd.Flags().BoolVar(&f.fetchSitemap, "sitemap", true, "读取 sitemap.xml / robots 中声明的 sitemap")
	cmd.Flags().BoolVar(&f.followRedirects, "follow-redirects", true, "跟随 3xx 跳转")
	cmd.Flags().BoolVar(&f.tryHTTPFallback, "http-fallback", true, "裸 host 的 https 失败后尝试 http")
	cmd.Flags().BoolVar(&f.skipTLSVerify, "skip-tls-verify", false, "跳过 TLS 证书校验")
	cmd.Flags().StringVar(&f.userAgent, "user-agent", "", "自定义 User-Agent")
	cmd.Flags().StringVarP(&f.outputPath, "output", "o", "", "输出文件（默认 stdout）")
	cmd.Flags().StringVar(&f.format, "format", "json", "输出格式：json|text")
	return cmd
}

func (f *flags) run(cmd *cobra.Command, args []string) error {
	targets, err := f.collectTargets()
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return fmt.Errorf("must provide --target / --target-file / --stdin")
	}
	cfg := webmeta.Config{
		Targets:         targets,
		Concurrency:     f.concurrency,
		Timeout:         time.Duration(f.timeoutSec) * time.Second,
		MaxBodyBytes:    int64(f.maxBodyKB) * 1024,
		MaxSitemapURLs:  f.maxSitemapURLs,
		MaxSitemaps:     f.maxSitemaps,
		FetchRobots:     f.fetchRobots,
		FetchSitemap:    f.fetchSitemap,
		FollowRedirects: f.followRedirects,
		TryHTTPFallback: f.tryHTTPFallback,
		SkipTLSVerify:   f.skipTLSVerify,
		UserAgent:       f.userAgent,
	}
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	res := webmeta.Collect(ctx, cfg)
	return f.emit(res)
}

func (f *flags) collectTargets() ([]string, error) {
	seen := map[string]struct{}{}
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" || strings.HasPrefix(s, "#") {
			return
		}
		k := strings.ToLower(s)
		if _, ok := seen[k]; ok {
			return
		}
		seen[k] = struct{}{}
		out = append(out, s)
	}
	for _, raw := range f.targets {
		for _, p := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ';' || r == '\n' || r == '\r' || r == '\t' }) {
			add(p)
		}
	}
	if f.targetFile != "" {
		fh, err := os.Open(f.targetFile)
		if err != nil {
			return nil, err
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

func (f *flags) emit(res *webmeta.Result) error {
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
	case "", "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(res)
	case "text":
		fmt.Fprintf(w, "webmeta: %d targets / ok=%d errors=%d emails=%d phones=%d icp=%d sitemap_urls=%d / %dms\n",
			res.Stats.Targets, res.Stats.OK, res.Stats.Errors, res.Stats.Emails, res.Stats.Phones, res.Stats.ICPNumbers, res.Stats.SitemapURLs, res.DurationMS)
		for _, r := range res.Reports {
			fmt.Fprintf(w, "\n=== %s ===\n", r.Input)
			fmt.Fprintf(w, "  url: %s\n  status: %d\n  title: %s\n", firstNonEmpty(r.FinalURL, r.URL), r.Status, r.Title)
			if len(r.ICPNumbers) > 0 {
				fmt.Fprintf(w, "  icp: %s\n", strings.Join(r.ICPNumbers, ", "))
			}
			if len(r.Emails) > 0 {
				fmt.Fprintf(w, "  emails: %s\n", strings.Join(r.Emails, ", "))
			}
			if len(r.Phones) > 0 {
				fmt.Fprintf(w, "  phones: %s\n", strings.Join(r.Phones, ", "))
			}
			if r.Err != "" {
				fmt.Fprintf(w, "  err: %s\n", r.Err)
			}
		}
		return nil
	default:
		return fmt.Errorf("unknown --format %q", f.format)
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
