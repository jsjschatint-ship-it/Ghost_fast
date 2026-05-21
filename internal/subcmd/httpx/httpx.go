// Package httpx is the `ghost httpx` subcommand: active HTTP liveness probing.
//
// It reads one or more target strings from -t / -T / --input-file / stdin,
// runs them through pkg/active/httpx.Prober, and writes results as JSON-lines
// (default) or as a *models.Asset list compatible with `output.Write`.
package httpx

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

	"github.com/wgpsec/ENScan/pkg/active/httpx"
	"github.com/wgpsec/ENScan/pkg/models"
	"github.com/wgpsec/ENScan/pkg/output"
)

// flags backs the command-line options. Defined at package scope so cobra can
// wire pointers, but kept private to this subcommand.
type flags struct {
	target          string
	targets         []string
	inputFile       string
	stdin           bool
	concurrency     int
	timeoutSec      int
	maxRedirects    int
	followRedirects bool
	ports           []int
	noFavicon       bool
	noDNS           bool
	schemesAuto     bool
	proxy           string
	userAgent       string
	insecure        bool
	outputPath      string
	format          string // jsonl|asset-json|asset-text
}

// New constructs the cobra command.
func New() *cobra.Command {
	f := &flags{}
	cmd := &cobra.Command{
		Use:   "httpx",
		Short: "HTTP/HTTPS 存活探测 + 指纹识别",
		Long: `ghost httpx 拿一组 URL/host/host:port 直接走一次主动探测，输出
  status / title / server / cert / favicon hash / tech 指纹

输入可来自:
  -t <single>           单目标
  -T <a,b,c>            多目标（逗号分隔）
  --input-file <path>   每行一个目标，# 开头跳过
  --stdin               从标准输入按行读取

输出格式 (--format):
  jsonl       每行一条 pkg/active/httpx.Result JSON（默认）
  asset-json  转成 models.Asset 数组 JSON
  asset-text  转成 models.Asset 文本表，复用 pkg/output 渲染`,
		RunE: f.run,
	}
	cmd.Flags().StringVarP(&f.target, "target", "t", "", "单目标")
	cmd.Flags().StringSliceVarP(&f.targets, "targets", "T", nil, "多目标，逗号分隔")
	cmd.Flags().StringVar(&f.inputFile, "input-file", "", "目标列表文件")
	cmd.Flags().BoolVar(&f.stdin, "stdin", false, "从 stdin 读目标")
	cmd.Flags().IntVar(&f.concurrency, "concurrency", 50, "并发数")
	cmd.Flags().IntVar(&f.timeoutSec, "timeout", 10, "单请求超时（秒）")
	cmd.Flags().IntVar(&f.maxRedirects, "max-redirects", 5, "最大重定向跳数")
	cmd.Flags().BoolVar(&f.followRedirects, "follow", true, "跟随重定向")
	cmd.Flags().IntSliceVar(&f.ports, "ports", []int{80, 443}, "无端口主机自动展开的端口列表（需 --schemes-auto）")
	cmd.Flags().BoolVar(&f.noFavicon, "no-favicon", false, "禁用 favicon hash 抓取")
	cmd.Flags().BoolVar(&f.noDNS, "no-dns", false, "禁用 DNS 解析（A/AAAA/CNAME）")
	cmd.Flags().BoolVar(&f.schemesAuto, "schemes-auto", true, "无 scheme 的 host 自动展开 http+https")
	cmd.Flags().StringVar(&f.proxy, "proxy", "", "HTTP/SOCKS5 代理 URL")
	cmd.Flags().StringVar(&f.userAgent, "user-agent", "Ghost/1.0 (httpx)", "User-Agent")
	cmd.Flags().BoolVarP(&f.insecure, "insecure", "k", true, "跳过 TLS 证书校验")
	cmd.Flags().StringVarP(&f.outputPath, "output", "o", "", "输出文件（默认 stdout）")
	cmd.Flags().StringVar(&f.format, "format", "jsonl", "输出格式：jsonl|asset-json|asset-text")
	return cmd
}

// run is the cobra RunE entry point.
func (f *flags) run(cmd *cobra.Command, args []string) error {
	inputs, err := f.collectInputs()
	if err != nil {
		return err
	}
	if len(inputs) == 0 {
		return fmt.Errorf("无输入目标；请使用 -t / -T / --input-file / --stdin")
	}

	prober := httpx.New(httpx.Config{
		Concurrency:     f.concurrency,
		Timeout:         time.Duration(f.timeoutSec) * time.Second,
		MaxRedirects:    f.maxRedirects,
		FollowRedirects: f.followRedirects,
		UserAgent:       f.userAgent,
		SchemesAuto:     f.schemesAuto,
		Ports:           f.ports,
		FetchFavicon:    !f.noFavicon,
		ResolveDNS:      !f.noDNS,
		Proxy:           f.proxy,
		SkipTLSVerify:   f.insecure,
	})

	ctx, cancel := context.WithCancel(cmd.Context())
	if ctx == nil {
		ctx, cancel = context.WithCancel(context.Background())
	}
	defer cancel()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Fprintln(os.Stderr, "[!] 收到中断信号，停止剩余探测")
		cancel()
	}()

	// Stream progress to stderr so it doesn't pollute stdout output.
	progress := func(done, total int, _ *httpx.Result) {
		if total > 1 {
			fmt.Fprintf(os.Stderr, "\r[httpx] %d/%d", done, total)
			if done == total {
				fmt.Fprintln(os.Stderr)
			}
		}
	}
	results := prober.Run(ctx, inputs, progress)
	return f.emit(results)
}

// collectInputs merges -t / -T / --input-file / --stdin, preserving order and
// deduplicating case-insensitively on the raw string.
func (f *flags) collectInputs() ([]string, error) {
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
	for _, t := range f.targets {
		for _, p := range strings.FieldsFunc(t, func(r rune) bool {
			return r == ',' || r == ';' || r == ' ' || r == '\t'
		}) {
			add(p)
		}
	}
	if f.inputFile != "" {
		fh, err := os.Open(f.inputFile)
		if err != nil {
			return nil, fmt.Errorf("打开 input-file: %w", err)
		}
		defer fh.Close()
		sc := bufio.NewScanner(fh)
		sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
		for sc.Scan() {
			line := sc.Text()
			if i := strings.Index(line, "#"); i >= 0 {
				line = line[:i]
			}
			add(line)
		}
		if err := sc.Err(); err != nil {
			return nil, fmt.Errorf("读 input-file: %w", err)
		}
	}
	if f.stdin {
		sc := bufio.NewScanner(os.Stdin)
		sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
		for sc.Scan() {
			add(sc.Text())
		}
		if err := sc.Err(); err != nil {
			return nil, fmt.Errorf("读 stdin: %w", err)
		}
	}
	return out, nil
}

// emit serialises the result slice according to the chosen format.
func (f *flags) emit(results []*httpx.Result) error {
	switch f.format {
	case "jsonl":
		return writeJSONL(f.outputPath, results)
	case "asset-json", "asset-text", "asset-yaml":
		assets := make([]*models.Asset, 0, len(results))
		for _, r := range results {
			if r == nil || r.Status == 0 {
				continue // skip transport failures from asset export
			}
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
		return fmt.Errorf("未知 --format: %s（应为 jsonl|asset-json|asset-text|asset-yaml）", f.format)
	}
}

// writeJSONL writes one JSON object per line, either to outputPath or stdout.
func writeJSONL(outputPath string, results []*httpx.Result) error {
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
