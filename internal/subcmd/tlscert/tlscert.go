// Package tlscert is the `ghost tlscert` subcommand: TLS handshake + crt.sh
// historical CT lookup + favicon-hash 集团关联.
package tlscert

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

	"github.com/wgpsec/ENScan/pkg/active/tlscert"
)

type flags struct {
	targets        []string
	targetsFile    string
	useStdin       bool
	ctlogDomains   []string
	faviconURLs    []string
	doLiveTLS      bool
	doCrtSh        bool
	doFavicon      bool
	concurrency    int
	tlsTimeoutSec  int
	httpTimeoutSec int
	crtshMaxRows   int
	userAgent      string
	output         string
	format         string
}

// New returns the cobra command.
func New() *cobra.Command {
	f := &flags{
		doLiveTLS: true,
		doFavicon: true,
	}
	cmd := &cobra.Command{
		Use:   "tlscert",
		Short: "TLS 证书 + 历史 CT + favicon 哈希集团关联",
		Long: `ghost tlscert 三件套（按需开关，默认 TLS+favicon）：

  • TLS handshake：拉 :443 leaf 证书，解 SAN/Issuer/SHA256 指纹，
    暴露所属"sister 域名"。
  • crt.sh：查证书透明度日志，给一个根域 → 历史所有 SAN，扩散
    出全公司子域宇宙（速度慢、限速；--ct 启用）。
  • favicon hash：抓 /favicon.ico → mmh3-32（Shodan / FOFA 的
    http.favicon.hash:<int> 反查关键值），用于跨集团资产关联。

输入:
  -t / --target     host 或 host:port（默认 :443，可重复）
  -T / --target-file 文件（一行一个）
  --stdin           从 stdin 读
  --ct-domain       crt.sh 查询根域（可重复，配合 --ct 使用）
  --favicon-url     直接给 /favicon.ico URL（可重复；不给则从 -t 推导）`,
		RunE: f.run,
	}
	cmd.Flags().StringSliceVarP(&f.targets, "target", "t", nil, "host[:port]，可重复或逗号分隔")
	cmd.Flags().StringVarP(&f.targetsFile, "target-file", "T", "", "目标文件，一行一个")
	cmd.Flags().BoolVar(&f.useStdin, "stdin", false, "从 stdin 读目标")
	cmd.Flags().StringSliceVar(&f.ctlogDomains, "ct-domain", nil, "crt.sh 查询的根域")
	cmd.Flags().StringSliceVar(&f.faviconURLs, "favicon-url", nil, "favicon URL 直接列表")
	cmd.Flags().BoolVar(&f.doLiveTLS, "tls", true, "执行 TLS handshake 阶段")
	cmd.Flags().BoolVar(&f.doCrtSh, "ct", false, "执行 crt.sh 阶段（默认关，限速）")
	cmd.Flags().BoolVar(&f.doFavicon, "favicon", true, "执行 favicon-hash 阶段")
	cmd.Flags().IntVar(&f.concurrency, "concurrency", 16, "并发数")
	cmd.Flags().IntVar(&f.tlsTimeoutSec, "tls-timeout", 8, "TLS 单次超时（秒）")
	cmd.Flags().IntVar(&f.httpTimeoutSec, "http-timeout", 15, "HTTP 单次超时（秒）")
	cmd.Flags().IntVar(&f.crtshMaxRows, "crtsh-max-rows", 5000, "crt.sh 单域最大行数")
	cmd.Flags().StringVar(&f.userAgent, "user-agent", "", "自定义 User-Agent")
	cmd.Flags().StringVarP(&f.output, "output", "o", "", "输出文件（默认 stdout）")
	cmd.Flags().StringVar(&f.format, "format", "json", "输出格式：json|text")
	return cmd
}

func (f *flags) run(cmd *cobra.Command, args []string) error {
	targets, err := f.collectTargets()
	if err != nil {
		return err
	}
	if len(targets) == 0 && len(f.faviconURLs) == 0 && len(f.ctlogDomains) == 0 {
		return fmt.Errorf("必须给至少一个目标 (-t/-T/--stdin) 或 --favicon-url 或 --ct-domain")
	}

	cfg := tlscert.Config{
		Targets:      targets,
		CTLogDomains: f.ctlogDomains,
		FaviconURLs:  f.faviconURLs,
		DoLiveTLS:    f.doLiveTLS,
		DoCrtSh:      f.doCrtSh,
		DoFavicon:    f.doFavicon,
		Concurrency:  f.concurrency,
		TLSTimeout:   time.Duration(f.tlsTimeoutSec) * time.Second,
		HTTPTimeout:  time.Duration(f.httpTimeoutSec) * time.Second,
		CrtShMaxRows: f.crtshMaxRows,
		UserAgent:    f.userAgent,
	}

	ctx, cancel := context.WithCancel(cmd.Context())
	if ctx == nil {
		ctx, cancel = context.WithCancel(context.Background())
	}
	defer cancel()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() { <-sigCh; cancel() }()

	res := tlscert.Run(ctx, cfg)
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
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	for _, raw := range f.targets {
		for _, p := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ';' }) {
			add(p)
		}
	}
	if f.targetsFile != "" {
		fh, err := os.Open(f.targetsFile)
		if err != nil {
			return nil, fmt.Errorf("open --target-file: %w", err)
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

func (f *flags) emit(res *tlscert.Result) error {
	w := os.Stdout
	if f.output != "" && f.output != "-" {
		fh, err := os.Create(f.output)
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
		fmt.Fprintf(w, "TLS Cert Scan: %d certs (%d ok / %d err) | %d CT rows (%d unique) | %d favicons | %dms\n",
			len(res.Certs), res.Stats.CertsOK, res.Stats.CertsErr,
			res.Stats.CTRows, res.Stats.CTUniqueNames,
			res.Stats.FaviconsHashed, res.DurationMS)
		if len(res.Certs) > 0 {
			fmt.Fprintln(w, "\n=== TLS Certificates ===")
			for _, c := range res.Certs {
				if c == nil {
					continue
				}
				if c.Err != "" {
					fmt.Fprintf(w, "  [err]  %s — %s\n", c.Target, c.Err)
					continue
				}
				fmt.Fprintf(w, "  [ok]   %s\n         CN=%s\n         SHA256=%s\n         SANs=%s\n",
					c.Target, c.SubjectCN, c.SHA256, strings.Join(c.SANs, ","))
			}
		}
		if len(res.Favicons) > 0 {
			fmt.Fprintln(w, "\n=== Favicon Hashes ===")
			for _, fav := range res.Favicons {
				if fav == nil {
					continue
				}
				if fav.Err != "" {
					fmt.Fprintf(w, "  [err]  %s — %s\n", fav.URL, fav.Err)
					continue
				}
				fmt.Fprintf(w, "  %s  mmh3=%d  md5=%s  size=%dB\n", fav.URL, fav.MMH3, fav.MD5, fav.BodyLen)
			}
		}
		if len(res.CTQueries) > 0 {
			fmt.Fprintln(w, "\n=== crt.sh ===")
			for _, q := range res.CTQueries {
				if q == nil {
					continue
				}
				if q.Err != "" {
					fmt.Fprintf(w, "  [err]  %s — %s\n", q.Domain, q.Err)
					continue
				}
				fmt.Fprintf(w, "  %s: %d rows / %d unique names%s\n",
					q.Domain, len(q.Rows), len(q.UniqueNames),
					tern(q.Truncated, " (truncated)", ""))
			}
		}
		return nil
	default:
		return fmt.Errorf("unknown --format %q", f.format)
	}
}

func tern(cond bool, a, b string) string {
	if cond {
		return a
	}
	return b
}
