// Package sensifile is the `ghost sensifile` subcommand: sensitive-path
// existence probes against a list of base URLs.
package sensifile

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/wgpsec/ENScan/pkg/active/sensifile"
)

type flags struct {
	urls         []string
	urlsFile     string
	paths        []string
	mediumOnly   bool
	concurrency  int
	timeoutSec   int
	maxBodyBytes int64
	output       string
	format       string
}

// New constructs the cobra subcommand.
func New() *cobra.Command {
	f := &flags{}
	cmd := &cobra.Command{
		Use:   "sensifile",
		Short: "敏感文件存在性探测 (.git / .env / actuator / swagger / DS_Store …)",
		Long: `ghost sensifile 对每个 URL 跑 HEAD→GET 一批高价值路径（默认 ~60 条），
仅判 200/206 + 内容自检（避免 SPA 200 fallback 假阳性）。`,
		RunE: f.run,
	}
	cmd.Flags().StringSliceVarP(&f.urls, "url", "u", nil, "目标根 URL（可重复或逗号分隔）")
	cmd.Flags().StringVarP(&f.urlsFile, "url-file", "U", "", "URL 文件，一行一个")
	cmd.Flags().StringSliceVar(&f.paths, "path", nil, "自定义路径（覆盖内置字典）")
	cmd.Flags().BoolVar(&f.mediumOnly, "medium-only", false, "丢弃 info-级别命中")
	cmd.Flags().IntVar(&f.concurrency, "concurrency", 20, "并发数")
	cmd.Flags().IntVar(&f.timeoutSec, "timeout", 10, "单次 HTTP 超时（秒）")
	cmd.Flags().Int64Var(&f.maxBodyBytes, "max-body", 1024, "单文件最大抓取字节")
	cmd.Flags().StringVarP(&f.output, "output", "o", "", "输出文件（默认 stdout）")
	cmd.Flags().StringVar(&f.format, "format", "json", "输出格式：json|text")
	return cmd
}

func (f *flags) run(cmd *cobra.Command, args []string) error {
	urls := collectURLs(f.urls, f.urlsFile)
	if len(urls) == 0 {
		return fmt.Errorf("must provide --url or --url-file")
	}
	cfg := sensifile.Config{
		BaseURLs:          urls,
		Paths:             f.paths,
		IncludeMediumOnly: f.mediumOnly,
		Concurrency:       f.concurrency,
		Timeout:           time.Duration(f.timeoutSec) * time.Second,
		MaxBodyBytes:      f.maxBodyBytes,
		FollowRedirects:   true,
	}
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	res := sensifile.Scan(ctx, cfg)
	return emit(f.output, f.format, res)
}

func collectURLs(list []string, file string) []string {
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
	for _, raw := range list {
		for _, p := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ';' }) {
			add(p)
		}
	}
	if file != "" {
		if data, err := os.ReadFile(file); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				add(line)
			}
		}
	}
	return out
}

func emit(out, format string, res *sensifile.Result) error {
	w := os.Stdout
	if out != "" && out != "-" {
		fh, err := os.Create(out)
		if err != nil {
			return err
		}
		defer fh.Close()
		w = fh
	}
	switch strings.ToLower(format) {
	case "", "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(res)
	case "text":
		fmt.Fprintf(w, "Sensifile: %d URLs × %d paths → %d findings / %dms\n",
			res.Stats.URLs, res.Stats.PathsPerURL, res.Stats.Findings, res.DurationMS)
		for _, f := range res.Findings {
			fmt.Fprintf(w, "  [%s] %s — %s  (%d, %s)\n", f.Severity, f.URL, f.Description, f.Status, f.ContentType)
		}
		return nil
	default:
		return fmt.Errorf("unknown --format %q", format)
	}
}
