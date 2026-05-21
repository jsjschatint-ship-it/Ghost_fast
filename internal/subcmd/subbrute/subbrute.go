// Package subbrute is the `ghost subbrute` subcommand: active subdomain
// brute-force discovery driven by pkg/active/subdomain.
package subbrute

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/wgpsec/ENScan/pkg/active/subdomain"
	"github.com/wgpsec/ENScan/pkg/models"
	"github.com/wgpsec/ENScan/pkg/output"
)

// flags carries CLI flag values. Kept private to this subcommand.
type flags struct {
	domain         string
	domains        []string
	wordlist       string
	resolvers      []string
	concurrency    int
	timeoutSec     int
	skipWildcard   bool
	wildcardProbes int
	retryPerQuery  int
	includeRoot    bool
	outputPath     string
	format         string // jsonl | asset-json | asset-text | asset-yaml | plain
	verbose        bool
}

// New constructs the cobra command.
func New() *cobra.Command {
	f := &flags{}
	cmd := &cobra.Command{
		Use:   "subbrute",
		Short: "子域名爆破（DNS 主动探测 + 通配符过滤）",
		Long: `ghost subbrute 用内置 / 自定义字典对目标根域做 DNS A/CNAME 主动爆破，自动检测并
过滤泛解析（wildcard）噪声，跨多家公共解析器轮询，输出活子域 + IP。

字典选择 --wordlist:
  builtin:top5000    内置 SecLists top 5k（默认）
  builtin:top20000   内置 SecLists top 20k
  <file path>        自定义字典文件（一行一个，# 注释）

输出 --format:
  jsonl              每行一条 pkg/active/subdomain.Result JSON
  plain              每行一个 FQDN（适合 pipe 给 httpx）
  asset-json|yaml|text  转 models.Asset 后走 pkg/output`,
		RunE: f.run,
	}
	cmd.Flags().StringVarP(&f.domain, "domain", "d", "", "单根域，如 example.com")
	cmd.Flags().StringSliceVarP(&f.domains, "domains", "D", nil, "多根域，逗号分隔")
	cmd.Flags().StringVarP(&f.wordlist, "wordlist", "w", "builtin:top5000", "字典：builtin:top5000 | builtin:top20000 | 文件路径")
	cmd.Flags().StringSliceVar(&f.resolvers, "resolvers", nil, "DNS 解析器列表 host:port（默认 Google/Cloudflare/Quad9/AliDNS/DNSPod/OpenDNS）")
	cmd.Flags().IntVar(&f.concurrency, "concurrency", 100, "并发数")
	cmd.Flags().IntVar(&f.timeoutSec, "timeout", 5, "单次 DNS 查询超时（秒）")
	cmd.Flags().BoolVar(&f.skipWildcard, "no-wildcard-filter", false, "禁用泛解析过滤")
	cmd.Flags().IntVar(&f.wildcardProbes, "wildcard-probes", 5, "泛解析探测的随机标签数")
	cmd.Flags().IntVar(&f.retryPerQuery, "retry", 0, "单条查询失败重试次数")
	cmd.Flags().BoolVar(&f.includeRoot, "include-root", false, "也对裸根域发起一次查询")
	cmd.Flags().StringVarP(&f.outputPath, "output", "o", "", "输出文件（默认 stdout）")
	cmd.Flags().StringVar(&f.format, "format", "jsonl", "输出格式：jsonl|plain|asset-json|asset-text|asset-yaml")
	cmd.Flags().BoolVarP(&f.verbose, "verbose", "v", false, "stderr 显示每条命中")
	return cmd
}

// run is the cobra RunE entry point.
func (f *flags) run(cmd *cobra.Command, args []string) error {
	domains := f.collectDomains()
	if len(domains) == 0 {
		return fmt.Errorf("必须指定 -d / -D 至少一个根域")
	}

	cfg := subdomain.Config{
		WordlistPath:   f.wordlist,
		Resolvers:      f.resolvers,
		Concurrency:    f.concurrency,
		Timeout:        time.Duration(f.timeoutSec) * time.Second,
		SkipWildcard:   f.skipWildcard,
		WildcardProbes: f.wildcardProbes,
		RetryPerQuery:  f.retryPerQuery,
		IncludeRoot:    f.includeRoot,
	}
	brute := subdomain.New(cfg)

	ctx, cancel := context.WithCancel(cmd.Context())
	if ctx == nil {
		ctx, cancel = context.WithCancel(context.Background())
	}
	defer cancel()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Fprintln(os.Stderr, "[!] 收到中断信号，停止爆破")
		cancel()
	}()

	// One progress bar per root domain so the user can see which domain we're on.
	all := make([]*subdomain.Result, 0, 128)
	for di, dom := range domains {
		if len(domains) > 1 {
			fmt.Fprintf(os.Stderr, "[%d/%d] root=%s\n", di+1, len(domains), dom)
		}
		var lastDone int
		progress := func(done, total int, last *subdomain.Result, hit bool) {
			if hit && f.verbose {
				fmt.Fprintf(os.Stderr, "+ %s\t%s\n", last.Name, strings.Join(last.IPs, ","))
			}
			if done-lastDone >= 200 || done == total {
				fmt.Fprintf(os.Stderr, "\r[subbrute %s] %d/%d", dom, done, total)
				if done == total {
					fmt.Fprintln(os.Stderr)
				}
				lastDone = done
			}
		}
		results, err := brute.Run(ctx, dom, progress)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] %s: %v\n", dom, err)
			continue
		}
		all = append(all, results...)
	}

	return f.emit(all)
}

// collectDomains merges -d / -D, deduplicating case-insensitively.
func (f *flags) collectDomains() []string {
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
	if f.domain != "" {
		add(f.domain)
	}
	for _, d := range f.domains {
		for _, p := range strings.FieldsFunc(d, func(r rune) bool {
			return r == ',' || r == ';' || r == ' ' || r == '\t'
		}) {
			add(p)
		}
	}
	return out
}

// emit serialises results in the requested format.
func (f *flags) emit(results []*subdomain.Result) error {
	switch f.format {
	case "jsonl":
		return writeJSONL(f.outputPath, results)
	case "plain":
		return writePlain(f.outputPath, results)
	case "asset-json", "asset-text", "asset-yaml":
		assets := make([]*models.Asset, 0, len(results))
		for _, r := range results {
			assets = append(assets, r.ToAsset())
		}
		fmtKind := output.FormatJSON
		switch f.format {
		case "asset-text":
			fmtKind = output.FormatText
		case "asset-yaml":
			fmtKind = output.FormatYAML
		}
		return output.Write(assets, fmtKind, f.outputPath)
	default:
		return fmt.Errorf("未知 --format: %s（应为 jsonl|plain|asset-json|asset-text|asset-yaml）", f.format)
	}
}

// writeJSONL writes one JSON object per line.
func writeJSONL(outputPath string, results []*subdomain.Result) error {
	w := os.Stdout
	if outputPath != "" && outputPath != "-" {
		fh, err := os.Create(outputPath)
		if err != nil {
			return fmt.Errorf("创建输出文件: %w", err)
		}
		defer fh.Close()
		w = fh
	}
	enc := json.NewEncoder(w)
	for _, r := range results {
		if r == nil {
			continue
		}
		if err := enc.Encode(r); err != nil {
			return fmt.Errorf("写 jsonl: %w", err)
		}
	}
	return nil
}

// writePlain writes one FQDN per line; suitable as input to `ghost httpx --stdin`.
func writePlain(outputPath string, results []*subdomain.Result) error {
	w := os.Stdout
	if outputPath != "" && outputPath != "-" {
		fh, err := os.Create(outputPath)
		if err != nil {
			return fmt.Errorf("创建输出文件: %w", err)
		}
		defer fh.Close()
		w = fh
	}
	for _, r := range results {
		if r == nil || r.Name == "" {
			continue
		}
		if _, err := fmt.Fprintln(w, r.Name); err != nil {
			return err
		}
	}
	return nil
}
