package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	asncmd "github.com/wgpsec/ENScan/internal/subcmd/asn"
	cdninfocmd "github.com/wgpsec/ENScan/internal/subcmd/cdninfo"
	"github.com/wgpsec/ENScan/internal/subcmd/dnsadv"
	dnsrecordcmd "github.com/wgpsec/ENScan/internal/subcmd/dnsrecord"
	"github.com/wgpsec/ENScan/internal/subcmd/extractkeys"
	httpxcmd "github.com/wgpsec/ENScan/internal/subcmd/httpx"
	"github.com/wgpsec/ENScan/internal/subcmd/importxlsx"
	jscrawlcmd "github.com/wgpsec/ENScan/internal/subcmd/jscrawl"
	portscancmd "github.com/wgpsec/ENScan/internal/subcmd/portscan"
	sensifilecmd "github.com/wgpsec/ENScan/internal/subcmd/sensifile"
	"github.com/wgpsec/ENScan/internal/subcmd/server"
	"github.com/wgpsec/ENScan/internal/subcmd/smoke"
	"github.com/wgpsec/ENScan/internal/subcmd/subbrute"
	tlscertcmd "github.com/wgpsec/ENScan/internal/subcmd/tlscert"
	"github.com/wgpsec/ENScan/internal/subcmd/verify"
	webmetacmd "github.com/wgpsec/ENScan/internal/subcmd/webmeta"
	whoisrdapcmd "github.com/wgpsec/ENScan/internal/subcmd/whoisrdap"
	"github.com/wgpsec/ENScan/pkg/config"
	"github.com/wgpsec/ENScan/pkg/models"
	"github.com/wgpsec/ENScan/pkg/output"
	"github.com/wgpsec/ENScan/pkg/registry"
	"github.com/wgpsec/ENScan/pkg/runner"
)

// Version metadata is injected at link time via -ldflags. See
// scripts/build-all.ps1 and .github/workflows/release.yml.
// Defaults below are used for `go run` / `go build` without -ldflags.
var (
	Version   = "dev"
	Commit    = "unknown"
	BuildTime = ""
)

var (
	cfgFile     string
	target      string
	targetsFile string
	targetsList []string
	sources     []string
	outputPath  string
	timeout     int
	proxy       string
	format      string
)

var rootCmd = &cobra.Command{
	Use:   "ghost",
	Short: "企业信息收集工具（Go 重构版）",
	Long: `Ghost 是一款面向 HW/SRC 的企业信息收集工具。
支持多引擎、多被动源、并发采集，兼容原 Python 版配置文件。`,
	RunE: run,
}

func init() {
	// 根命令默认行为是 scan（保持向后兼容）；这些 flag 仅作用于根 RunE
	rootCmd.Flags().StringVarP(&cfgFile, "config", "c", "config.yaml", "配置文件路径")
	rootCmd.Flags().StringVarP(&target, "target", "t", "", "单目标（域名/公司/IP/URL）；与 -T/--targets-file 二选一/可同时给")
	rootCmd.Flags().StringSliceVarP(&targetsList, "targets", "T", []string{}, "多目标，逗号分隔，例如 -T qq.com,baidu.com")
	rootCmd.Flags().StringVar(&targetsFile, "targets-file", "", "目标列表文件，一行一个；# 开头跳过；与 -t/-T 自动合并去重")
	rootCmd.Flags().StringSliceVarP(&sources, "source", "s", []string{}, "指定数据源（默认使用配置文件启用项）")
	rootCmd.Flags().StringVarP(&outputPath, "output", "o", "", "输出文件（默认标准输出）")
	rootCmd.Flags().StringVar(&format, "format", "text", "输出格式（json|yaml|text）")
	rootCmd.Flags().IntVar(&timeout, "timeout", 30, "全局超时（秒）")
	rootCmd.Flags().StringVar(&proxy, "proxy", "", "全局代理（http://127.0.0.1:8080）")

	// 注册子命令
	rootCmd.AddCommand(server.New())
	rootCmd.AddCommand(smoke.New())
	rootCmd.AddCommand(importxlsx.New())
	rootCmd.AddCommand(verify.New())
	rootCmd.AddCommand(extractkeys.New())
	rootCmd.AddCommand(httpxcmd.New())
	rootCmd.AddCommand(subbrute.New())
	rootCmd.AddCommand(portscancmd.New())
	rootCmd.AddCommand(dnsadv.New())
	rootCmd.AddCommand(jscrawlcmd.New())
	rootCmd.AddCommand(tlscertcmd.New())
	rootCmd.AddCommand(dnsrecordcmd.New())
	rootCmd.AddCommand(sensifilecmd.New())
	rootCmd.AddCommand(cdninfocmd.New())
	rootCmd.AddCommand(asncmd.New())
	rootCmd.AddCommand(whoisrdapcmd.New())
	rootCmd.AddCommand(webmetacmd.New())
	rootCmd.AddCommand(newVersionCmd())
}

// newVersionCmd surfaces the build metadata injected via -ldflags so users
// can verify which binary they're running (and report it in bug reports).
func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "显示版本 / commit / 编译时间",
		Run: func(cmd *cobra.Command, args []string) {
			bt := BuildTime
			if bt == "" {
				bt = "unknown"
			}
			fmt.Printf("ghost %s\n", Version)
			fmt.Printf("  commit:     %s\n", Commit)
			fmt.Printf("  build time: %s\n", bt)
		},
	}
}

// collectTargets 把 -t / -T / --targets-file 三个来源合并 + 去重 + 顺序保留
func collectTargets() ([]string, error) {
	seen := map[string]struct{}{}
	out := make([]string, 0, 8)
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" || strings.HasPrefix(s, "#") {
			return
		}
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	if target != "" {
		add(target)
	}
	for _, t := range targetsList {
		// 允许 -T qq.com,baidu.com（cobra StringSlice 已切过逗号）
		// 同时兼容空白 / 分号
		for _, p := range strings.FieldsFunc(t, func(r rune) bool {
			return r == ',' || r == ';' || r == ' ' || r == '\t'
		}) {
			add(p)
		}
	}
	if targetsFile != "" {
		f, err := os.Open(targetsFile)
		if err != nil {
			return nil, fmt.Errorf("打开 targets-file: %w", err)
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for scanner.Scan() {
			line := scanner.Text()
			// 行内允许 # 注释
			if i := strings.Index(line, "#"); i >= 0 {
				line = line[:i]
			}
			add(line)
		}
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("读 targets-file: %w", err)
		}
	}
	return out, nil
}

func run(cmd *cobra.Command, args []string) error {
	targets, err := collectTargets()
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return fmt.Errorf("必须指定目标 -t / -T / --targets-file 至少一个")
	}

	// 加载配置
	cfg, err := config.LoadFromFile(cfgFile)
	if err != nil {
		return fmt.Errorf("加载配置: %w", err)
	}

	// 覆盖配置
	if timeout > 0 {
		cfg.Runner.Timeout = timeout
	}
	if proxy != "" {
		cfg.Runner.Proxy = proxy
	}
	if len(sources) > 0 {
		cfg.Runner.EnabledSources = sources
	}

	// 初始化全部数据源（引擎 + 被动 + misc_apis 系列）
	allSources := registry.AllSources()

	// 合并引擎与 sources 配置
	mergedConfigs := make(map[string]any)
	for k, v := range cfg.Sources {
		mergedConfigs[k] = v
	}
	for name, ec := range cfg.Engines {
		m := map[string]any{}
		if ec.Key != "" {
			m["key"] = ec.Key
		}
		if len(ec.Keys) > 0 {
			m["keys"] = ec.Keys
		}
		if ec.Proxy != "" {
			m["proxy"] = ec.Proxy
		}
		if ec.Timeout > 0 {
			m["timeout"] = ec.Timeout
		}
		if ec.Size > 0 {
			m["size"] = ec.Size
		}
		mergedConfigs[name] = m
	}

	runnerCfg := &runner.Config{
		EnabledSources: cfg.Runner.EnabledSources,
		SourceConfigs:  mergedConfigs,
		Proxy:          cfg.Runner.Proxy,
		UserAgent:      cfg.Runner.UserAgent,
		MaxConcurrency: cfg.Runner.MaxConcurrency,
		Timeout:        cfg.Runner.Timeout,
	}
	r := runner.NewRunner(runnerCfg, allSources)

	// 全局超时 = baseTimeout × 目标数（与 server 多目标策略保持一致），保证一个慢目标不拖死后面的
	baseTimeout := time.Duration(cfg.Runner.Timeout) * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), baseTimeout*time.Duration(len(targets)))
	defer cancel()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
	}()

	// 多目标顺序跑，结果合并；单目标场景与原行为完全一致。
	var all []*models.Asset
	var firstErr error
	for i, t := range targets {
		if len(targets) > 1 {
			fmt.Fprintf(os.Stderr, "[%d/%d] target=%s\n", i+1, len(targets), t)
		}
		subCtx, subCancel := context.WithTimeout(ctx, baseTimeout)
		batch, err := r.Run(subCtx, t)
		subCancel()
		if err != nil && firstErr == nil {
			firstErr = err
		}
		all = append(all, batch...)
		if ctx.Err() != nil {
			fmt.Fprintln(os.Stderr, "[!] 全局超时，停止剩余目标")
			break
		}
	}
	if firstErr != nil && len(all) == 0 {
		return fmt.Errorf("运行失败: %w", firstErr)
	}

	// 输出
	outFormat := output.Format(format)
	if err := output.Write(all, outFormat, outputPath); err != nil {
		return fmt.Errorf("输出失败: %w", err)
	}
	return nil
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
