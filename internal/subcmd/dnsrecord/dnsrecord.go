// Package dnsrecord is the `ghost dnsrecord` subcommand: pull every common
// DNS record type for a domain + classify TXT-record verification tokens.
package dnsrecord

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/wgpsec/ENScan/pkg/active/dnsrecord"
)

type flags struct {
	domain     string
	domains    []string
	domainFile string
	resolvers  []string
	timeoutSec int
	skipDKIM   bool
	skipSRV    bool
	output     string
	format     string
}

// New constructs the cobra subcommand.
func New() *cobra.Command {
	f := &flags{}
	cmd := &cobra.Command{
		Use:   "dnsrecord",
		Short: "全类型 DNS 枚举 + TXT 验证 token 解析",
		Long: `ghost dnsrecord 一次性拉一个域名的所有常用 DNS 记录：
  A/AAAA/MX/TXT/SOA/NS/CAA/CNAME/SRV + _dmarc 子域 TXT + 常见 DKIM selector。
TXT 记录还会被识别为 SaaS 验证 token（GitHub/Google/AWS/Atlassian/钉钉/飞书…）。`,
		RunE: f.run,
	}
	cmd.Flags().StringVarP(&f.domain, "domain", "d", "", "根域名（单个）")
	cmd.Flags().StringSliceVarP(&f.domains, "domains", "D", nil, "多个根域名（可重复或逗号分隔）")
	cmd.Flags().StringVar(&f.domainFile, "domain-file", "", "域名文件，一行一个")
	cmd.Flags().StringSliceVar(&f.resolvers, "resolver", nil, "DNS 解析器（默认 1.1.1.1 / 8.8.8.8 / 223.5.5.5）")
	cmd.Flags().IntVar(&f.timeoutSec, "timeout", 5, "单次 DNS 查询超时（秒）")
	cmd.Flags().BoolVar(&f.skipDKIM, "skip-dkim", false, "跳过 DKIM 探测")
	cmd.Flags().BoolVar(&f.skipSRV, "skip-srv", false, "跳过 SRV 探测")
	cmd.Flags().StringVarP(&f.output, "output", "o", "", "输出文件（默认 stdout）")
	cmd.Flags().StringVar(&f.format, "format", "json", "输出格式：json|text")
	return cmd
}

func (f *flags) run(cmd *cobra.Command, args []string) error {
	domains := collectDomains(f.domain, f.domains, f.domainFile)
	if len(domains) == 0 {
		return fmt.Errorf("must provide --domain / --domains / --domain-file")
	}
	cfg := dnsrecord.Config{
		Resolvers: f.resolvers,
		Timeout:   time.Duration(f.timeoutSec) * time.Second,
		SkipDKIM:  f.skipDKIM,
		SkipSRV:   f.skipSRV,
	}
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	var results []*dnsrecord.Result
	for _, d := range domains {
		results = append(results, dnsrecord.Lookup(ctx, d, cfg))
	}
	return emit(f.output, f.format, results)
}

func collectDomains(single string, list []string, file string) []string {
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
	add(single)
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

func emit(out, format string, results []*dnsrecord.Result) error {
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
		if len(results) == 1 {
			return enc.Encode(results[0])
		}
		return enc.Encode(results)
	case "text":
		for _, r := range results {
			fmt.Fprintf(w, "=== %s (%d records, %d tokens, %dms) ===\n", r.Domain, r.Stats.Total, r.Stats.TokensCount, r.DurationMS)
			for _, rec := range r.Records {
				fmt.Fprintf(w, "  [%s] %s = %s\n", rec.Type, rec.Name, rec.Value)
			}
			if len(r.Tokens) > 0 {
				fmt.Fprintln(w, "  --- TXT verification tokens ---")
				for _, m := range r.Tokens {
					fmt.Fprintf(w, "    %s (%s) %s\n", m.Provider, m.Type, m.Value)
				}
			}
			if r.Email.SPF != "" || r.Email.DMARC != "" {
				fmt.Fprintf(w, "  email: spf=%q dmarc-policy=%q mx=%v includes=%v\n",
					r.Email.SPF, r.Email.DMARCPolicy, r.Email.MXProviders, r.Email.SPFIncludes)
			}
		}
		return nil
	default:
		return fmt.Errorf("unknown --format %q", format)
	}
}
