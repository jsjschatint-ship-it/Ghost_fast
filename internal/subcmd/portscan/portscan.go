// Package portscan is the `ghost portscan` subcommand: TCP-connect port
// scanner driven by pkg/active/portscan.
package portscan

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

	"github.com/wgpsec/ENScan/pkg/active/portscan"
	"github.com/wgpsec/ENScan/pkg/models"
	"github.com/wgpsec/ENScan/pkg/output"
)

// flags carries CLI flag values.
type flags struct {
	target             string
	targets            []string
	inputFile          string
	useStdin           bool
	preset             string
	portsRange         string
	concurrency        int
	perHostConcurrency int
	timeoutMs          int
	retryTimeoutMs     int
	retryPerPort       int
	noBanner           bool
	bannerTimeoutMs    int
	skipResolve        bool
	outputPath         string
	format             string
	verbose            bool
}

// New constructs the cobra command.
func New() *cobra.Command {
	f := &flags{}
	cmd := &cobra.Command{
		Use:   "portscan",
		Short: "TCP 端口扫描（connect 扫 + banner + 自适应重试）",
		Long: `ghost portscan 用 TCP connect 扫描目标 IP / 主机的开放端口，自动采集 banner，
单 IP 限并发避免触发 SYN-flood 防护误关。

输入来源:
  -t / --target           单目标
  -T / --targets          多目标，逗号分隔
  --input-file <path>     一行一个目标
  --stdin                 从 stdin 读（每行一个）

端口选择 --preset / --ports:
  --preset top100         nmap top-100 频率 TCP 端口（默认）
  --preset top1000        nmap top-1000 频率 TCP 端口
  --preset all            全量 1-65535（慢！）
  --ports "80,443,8000-8100"   显式端口范围（覆盖 preset）

输出 --format:
  jsonl                   每行一条 portscan.Result JSON
  plain                   每行一个 ip:port（适合 pipe 给 httpx / nuclei）
  asset-json|yaml|text    转 models.Asset 后走 pkg/output`,
		RunE: f.run,
	}
	cmd.Flags().StringVarP(&f.target, "target", "t", "", "单目标 host/IP")
	cmd.Flags().StringSliceVarP(&f.targets, "targets", "T", nil, "多目标，逗号分隔")
	cmd.Flags().StringVar(&f.inputFile, "input-file", "", "目标文件，一行一个")
	cmd.Flags().BoolVar(&f.useStdin, "stdin", false, "从 stdin 读取目标")
	cmd.Flags().StringVar(&f.preset, "preset", "top100", "端口预设：top100|top1000|all")
	cmd.Flags().StringVar(&f.portsRange, "ports", "", "端口范围（如 80,443,8000-8100），覆盖 preset")
	cmd.Flags().IntVar(&f.concurrency, "concurrency", 500, "全局并发上限")
	cmd.Flags().IntVar(&f.perHostConcurrency, "per-host", 20, "单主机并发上限（防触发 SYN-flood 防护）")
	cmd.Flags().IntVar(&f.timeoutMs, "timeout", 1000, "首次连接超时（毫秒）")
	cmd.Flags().IntVar(&f.retryTimeoutMs, "retry-timeout", 3000, "重试连接超时（毫秒）")
	cmd.Flags().IntVar(&f.retryPerPort, "retry", 2, "单端口失败重试次数")
	cmd.Flags().BoolVar(&f.noBanner, "no-banner", false, "禁用 banner 抓取")
	cmd.Flags().IntVar(&f.bannerTimeoutMs, "banner-timeout", 1500, "banner 读取超时（毫秒）")
	cmd.Flags().BoolVar(&f.skipResolve, "skip-resolve", false, "跳过 DNS 解析（输入已是 IP）")
	cmd.Flags().StringVarP(&f.outputPath, "output", "o", "", "输出文件（默认 stdout）")
	cmd.Flags().StringVar(&f.format, "format", "jsonl", "输出格式：jsonl|plain|asset-json|asset-text|asset-yaml")
	cmd.Flags().BoolVarP(&f.verbose, "verbose", "v", false, "stderr 显示每条命中")
	return cmd
}

// run is the cobra RunE entry point.
func (f *flags) run(cmd *cobra.Command, args []string) error {
	targets, err := f.collectTargets()
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return fmt.Errorf("必须指定 -t / -T / --input-file / --stdin 中的至少一个目标来源")
	}

	cfg := portscan.Config{
		PortPreset:         f.preset,
		PortRange:          f.portsRange,
		Concurrency:        f.concurrency,
		PerHostConcurrency: f.perHostConcurrency,
		Timeout:            time.Duration(f.timeoutMs) * time.Millisecond,
		RetryTimeout:       time.Duration(f.retryTimeoutMs) * time.Millisecond,
		RetryPerPort:       f.retryPerPort,
		GrabBanner:         !f.noBanner,
		BannerTimeout:      time.Duration(f.bannerTimeoutMs) * time.Millisecond,
		SkipResolve:        f.skipResolve,
	}
	scanner := portscan.New(cfg)

	ctx, cancel := context.WithCancel(cmd.Context())
	if ctx == nil {
		ctx, cancel = context.WithCancel(context.Background())
	}
	defer cancel()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Fprintln(os.Stderr, "[!] 收到中断信号，停止扫描")
		cancel()
	}()

	var lastDone int
	progress := func(done, total int, last *portscan.Result) {
		if last != nil && f.verbose {
			banner := last.Banner
			if len(banner) > 60 {
				banner = banner[:60] + "..."
			}
			fmt.Fprintf(os.Stderr, "+ %s:%d\t%s\t%s\n", last.IP, last.Port, last.Service, banner)
		}
		if done-lastDone >= 200 || done == total {
			fmt.Fprintf(os.Stderr, "\r[portscan] %d/%d", done, total)
			if done == total {
				fmt.Fprintln(os.Stderr)
			}
			lastDone = done
		}
	}

	results, err := scanner.Run(ctx, targets, progress)
	if err != nil {
		return err
	}
	return f.emit(results)
}

// collectTargets merges -t / -T / --input-file / --stdin, deduping case-insensitively.
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
	if f.target != "" {
		add(f.target)
	}
	for _, raw := range f.targets {
		for _, p := range strings.FieldsFunc(raw, func(r rune) bool {
			return r == ',' || r == ';' || r == ' ' || r == '\t'
		}) {
			add(p)
		}
	}
	if f.inputFile != "" {
		fh, err := os.Open(f.inputFile)
		if err != nil {
			return nil, fmt.Errorf("open --input-file: %w", err)
		}
		defer fh.Close()
		sc := bufio.NewScanner(fh)
		sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
		for sc.Scan() {
			add(sc.Text())
		}
		if err := sc.Err(); err != nil {
			return nil, fmt.Errorf("read --input-file: %w", err)
		}
	}
	if f.useStdin {
		sc := bufio.NewScanner(os.Stdin)
		sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
		for sc.Scan() {
			add(sc.Text())
		}
		if err := sc.Err(); err != nil {
			return nil, fmt.Errorf("read stdin: %w", err)
		}
	}
	return out, nil
}

// emit serialises results in the requested format.
func (f *flags) emit(results []*portscan.Result) error {
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

func writeJSONL(outputPath string, results []*portscan.Result) error {
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

func writePlain(outputPath string, results []*portscan.Result) error {
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
		if r == nil || r.IP == "" {
			continue
		}
		if _, err := fmt.Fprintf(w, "%s:%d\n", r.IP, r.Port); err != nil {
			return err
		}
	}
	return nil
}
