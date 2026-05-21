// Package dnsadv is the `ghost dnsadv` subcommand: AXFR zone transfer +
// subdomain takeover detection driven by pkg/active/dnsadv.
package dnsadv

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

	"github.com/wgpsec/ENScan/pkg/active/dnsadv"
)

// flags carries CLI flag values.
type flags struct {
	domain               string
	subdomains           []string
	subdomainsFile       string
	useStdin             bool
	mode                 string
	resolvers            []string
	axfrTimeoutSec       int
	takeoverConcurrency  int
	takeoverTimeoutSec   int
	includeInformational bool
	outputPath           string
	format               string
}

// New constructs the cobra command.
func New() *cobra.Command {
	f := &flags{}
	cmd := &cobra.Command{
		Use:   "dnsadv",
		Short: "DNS 高级：AXFR 区域传送 + 子域接管检测",
		Long: `ghost dnsadv 做两件事：

  ① AXFR 区域传送 (zone transfer)
     对根域的每台权威 NS 发起 AXFR 查询；正常配置的 NS 应当拒绝（REFUSED），
     如果返回了整张 zone 文件 → 严重信息泄漏，整域所有内部主机暴露。

  ② 子域接管检测 (subdomain takeover)
     检查每个子域的 CNAME 链是否指向已注销/未声明的 SaaS（GitHub Pages /
     S3 / Heroku / Shopify / Vercel / Netlify 等 27+ 家），再 HTTP 探测验证
     "is available" / "NoSuchBucket" 等指纹字符串，确认可接管。

输入：
  -d / --domain          根域（AXFR + takeover 用作 zone）
  -s / --subdomains      子域列表（逗号分隔，takeover 用）
  -S / --subdomains-file 子域文件（一行一个）
  --stdin                从 stdin 读子域

模式 --mode:
  both       AXFR + takeover （默认）
  axfr       仅 AXFR
  takeover   仅子域接管`,
		RunE: f.run,
	}
	cmd.Flags().StringVarP(&f.domain, "domain", "d", "", "根域，如 example.com")
	cmd.Flags().StringSliceVarP(&f.subdomains, "subdomains", "s", nil, "子域列表，逗号分隔")
	cmd.Flags().StringVarP(&f.subdomainsFile, "subdomains-file", "S", "", "子域文件，一行一个")
	cmd.Flags().BoolVar(&f.useStdin, "stdin", false, "从 stdin 读子域")
	cmd.Flags().StringVar(&f.mode, "mode", "both", "运行模式：both|axfr|takeover")
	cmd.Flags().StringSliceVar(&f.resolvers, "resolvers", nil, "DNS 解析器列表 host:port（默认 Google/Cloudflare/AliDNS）")
	cmd.Flags().IntVar(&f.axfrTimeoutSec, "axfr-timeout", 8, "AXFR 查询超时（秒）")
	cmd.Flags().IntVar(&f.takeoverConcurrency, "takeover-concurrency", 30, "子域接管检测并发")
	cmd.Flags().IntVar(&f.takeoverTimeoutSec, "takeover-timeout", 6, "子域接管 HTTP 超时（秒）")
	cmd.Flags().BoolVar(&f.includeInformational, "include-informational", false, "也输出已修复 / 信息性 CNAME 命中")
	cmd.Flags().StringVarP(&f.outputPath, "output", "o", "", "输出文件（默认 stdout）")
	cmd.Flags().StringVar(&f.format, "format", "json", "输出格式：json|jsonl|text")
	return cmd
}

// run is the cobra RunE entry point.
func (f *flags) run(cmd *cobra.Command, args []string) error {
	mode := strings.ToLower(strings.TrimSpace(f.mode))
	if mode == "" {
		mode = "both"
	}
	if f.domain == "" && mode != "takeover" {
		return fmt.Errorf("AXFR 模式必须指定 -d / --domain")
	}
	subs, err := f.collectSubdomains()
	if err != nil {
		return err
	}
	if mode == "takeover" && len(subs) == 0 {
		return fmt.Errorf("takeover 模式必须通过 -s / -S / --stdin 提供子域列表")
	}

	cfg := dnsadv.Config{
		Mode:                mode,
		Resolvers:           f.resolvers,
		AXFRTimeout:         time.Duration(f.axfrTimeoutSec) * time.Second,
		TakeoverConcurrency: f.takeoverConcurrency,
		TakeoverHTTPTimeout: time.Duration(f.takeoverTimeoutSec) * time.Second,
		IncludeUnvulnerable: f.includeInformational,
	}
	scanner := dnsadv.New(cfg)

	ctx, cancel := context.WithCancel(cmd.Context())
	if ctx == nil {
		ctx, cancel = context.WithCancel(context.Background())
	}
	defer cancel()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() { <-sigCh; cancel() }()

	res := scanner.Scan(ctx, f.domain, subs)
	return f.emit(res)
}

// collectSubdomains merges -s / -S / --stdin, deduplicating case-insensitively.
func (f *flags) collectSubdomains() ([]string, error) {
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
	for _, raw := range f.subdomains {
		for _, p := range strings.FieldsFunc(raw, func(r rune) bool {
			return r == ',' || r == ';' || r == ' ' || r == '\t'
		}) {
			add(p)
		}
	}
	if f.subdomainsFile != "" {
		fh, err := os.Open(f.subdomainsFile)
		if err != nil {
			return nil, fmt.Errorf("open --subdomains-file: %w", err)
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
func (f *flags) emit(res *dnsadv.Result) error {
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
		// Emit AXFR results then takeover results, one per line.
		enc := json.NewEncoder(w)
		for _, ax := range res.AXFR {
			if err := enc.Encode(ax); err != nil {
				return err
			}
		}
		for _, tk := range res.Takeovers {
			if err := enc.Encode(tk); err != nil {
				return err
			}
		}
		return nil
	case "text":
		fmt.Fprintf(w, "DNS Advanced Scan: %s (took %dms)\n", res.Domain, res.DurationMS)
		if len(res.AXFR) > 0 {
			fmt.Fprintln(w, "\n=== AXFR Zone Transfer ===")
			for _, ax := range res.AXFR {
				if ax.Success {
					fmt.Fprintf(w, "  [VULN] %s @ %s — %d records (%dms)%s\n",
						ax.Domain, ax.NameServer, ax.RecordCount, ax.DurationMS,
						boolStr(ax.Truncated, " [truncated]", ""))
					for _, r := range ax.Records[:min(10, len(ax.Records))] {
						fmt.Fprintf(w, "    %s\n", r)
					}
					if ax.RecordCount > 10 {
						fmt.Fprintf(w, "    ... (%d more)\n", ax.RecordCount-10)
					}
				} else {
					fmt.Fprintf(w, "  [ok]   %s @ %s — %s\n", ax.Domain, ax.NameServer, firstNonEmpty(ax.Err, "no records"))
				}
			}
		}
		if len(res.Takeovers) > 0 {
			fmt.Fprintln(w, "\n=== Subdomain Takeover ===")
			for _, tk := range res.Takeovers {
				marker := "[?]"
				if tk.Vulnerable {
					marker = "[VULN]"
				}
				fmt.Fprintf(w, "  %s %s → %s (%s)%s\n", marker, tk.Subdomain, tk.CNAME, tk.Service,
					boolStr(tk.Evidence != "", "  evidence="+tk.Evidence, ""))
			}
		}
		return nil
	default:
		return fmt.Errorf("unknown --format %q", f.format)
	}
}

func boolStr(b bool, t, f string) string {
	if b {
		return t
	}
	return f
}

func firstNonEmpty(parts ...string) string {
	for _, p := range parts {
		if p != "" {
			return p
		}
	}
	return ""
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
