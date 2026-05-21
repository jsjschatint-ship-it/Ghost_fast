// Package whoisrdap is the `ghost whoisrdap` subcommand.
package whoisrdap

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/wgpsec/ENScan/pkg/active/whoisrdap"
)

type flags struct {
	inputs       []string
	inputFile    string
	skipRDAP     bool
	skipWHOIS    bool
	httpSec      int
	whoisSec     int
	concurrency  int
	reverseWHOIS bool
	reverseKey   string
	maxSiblings  int
	output       string
	format       string
	includeRaw   bool
}

// New constructs the cobra subcommand.
func New() *cobra.Command {
	f := &flags{}
	cmd := &cobra.Command{
		Use:   "whoisrdap",
		Short: "实时 RDAP + WHOIS 查询（域名 / IP）",
		Long: `ghost whoisrdap 同时跑 RDAP（结构化 JSON）+ WHOIS（plaintext TCP/43）：
  - RDAP 优先解析联系人 vCard、events、entities
  - WHOIS 补齐 RDAP 没给的 registrant email / 创建时间 / NS / Status
两边合并到一份 Record。命中“同 registrant email”可横向找姊妹域。`,
		RunE: f.run,
	}
	cmd.Flags().StringSliceVarP(&f.inputs, "input", "i", nil, "域名或 IP（可重复或逗号分隔）")
	cmd.Flags().StringVar(&f.inputFile, "input-file", "", "输入文件，一行一个")
	cmd.Flags().BoolVar(&f.skipRDAP, "skip-rdap", false, "跳过 RDAP 阶段")
	cmd.Flags().BoolVar(&f.skipWHOIS, "skip-whois", false, "跳过 WHOIS 阶段")
	cmd.Flags().IntVar(&f.httpSec, "http-timeout", 12, "RDAP HTTP 超时（秒）")
	cmd.Flags().IntVar(&f.whoisSec, "whois-timeout", 8, "WHOIS TCP 超时（秒）")
	cmd.Flags().IntVar(&f.concurrency, "concurrency", 4, "并发数")
	cmd.Flags().BoolVar(&f.reverseWHOIS, "reverse-whois", false, "启用反查 WHOIS：按注册邮箱/组织/注册人横向找姊妹域")
	cmd.Flags().StringVar(&f.reverseKey, "whoisxml-key", "", "WhoisXMLAPI Reverse WHOIS key（可选；留空回退 ViewDNS）")
	cmd.Flags().IntVar(&f.maxSiblings, "max-siblings", 100, "每输入最多保留姊妹域数量")
	cmd.Flags().StringVarP(&f.output, "output", "o", "", "输出文件（默认 stdout）")
	cmd.Flags().StringVar(&f.format, "format", "json", "输出格式：json|text")
	cmd.Flags().BoolVar(&f.includeRaw, "include-raw", false, "JSON 输出包含 rdap_json / whois_text 原文")
	return cmd
}

func (f *flags) run(cmd *cobra.Command, args []string) error {
	inputs := collect(f.inputs, f.inputFile)
	if len(inputs) == 0 {
		return fmt.Errorf("must provide --input or --input-file")
	}
	cfg := whoisrdap.Config{
		Inputs:            inputs,
		DoRDAP:            !f.skipRDAP,
		DoWHOIS:           !f.skipWHOIS,
		DoReverseWHOIS:    f.reverseWHOIS,
		ReverseWhoisKey:   f.reverseKey,
		MaxSiblingDomains: f.maxSiblings,
		HTTPTimeout:       time.Duration(f.httpSec) * time.Second,
		WHOISTimeout:      time.Duration(f.whoisSec) * time.Second,
		Concurrency:       f.concurrency,
	}
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	res := whoisrdap.Lookup(ctx, cfg)
	if !f.includeRaw {
		// Strip the bulky raw bodies — most callers don't want them in the JSON.
		for _, r := range res.Records {
			r.Raw = nil
		}
	}
	return emit(f.output, f.format, res)
}

func collect(list []string, file string) []string {
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

func emit(out, format string, res *whoisrdap.Result) error {
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
		fmt.Fprintf(w, "WHOIS+RDAP: %d inputs / RDAP=%d WHOIS=%d failed=%d uniq-emails=%d (%dms)\n",
			res.Stats.Inputs, res.Stats.RDAPOK, res.Stats.WHOISOK, res.Stats.Failed, res.Stats.UniqueEmails, res.DurationMS)
		for _, r := range res.Records {
			fmt.Fprintf(w, "=== %s [%s] ===\n", r.Input, r.Kind)
			if r.Registrar != "" {
				fmt.Fprintf(w, "  registrar: %s\n", r.Registrar)
			}
			if r.CreatedAt != "" || r.ExpiresAt != "" {
				fmt.Fprintf(w, "  dates: created=%s updated=%s expires=%s\n", r.CreatedAt, r.UpdatedAt, r.ExpiresAt)
			}
			if len(r.Nameservers) > 0 {
				fmt.Fprintf(w, "  ns: %v\n", r.Nameservers)
			}
			if len(r.Status) > 0 {
				fmt.Fprintf(w, "  status: %v\n", r.Status)
			}
			for _, c := range r.Contacts {
				fmt.Fprintf(w, "  contact[%s] name=%q org=%q email=%q country=%q\n", c.Role, c.Name, c.Organization, c.Email, c.Country)
			}
			if len(r.SiblingDomains) > 0 {
				fmt.Fprintln(w, "  sibling domains:")
				for _, s := range r.SiblingDomains {
					fmt.Fprintf(w, "    [%s] %s  pivot=%s\n", s.Source, s.Domain, s.Pivot)
				}
			}
			if r.IPNetwork != "" {
				fmt.Fprintf(w, "  ip-network: %s  org: %s  country: %s\n", r.IPNetwork, r.IPOrg, r.IPCountry)
			}
			if r.Err != "" && len(r.Sources) == 0 {
				fmt.Fprintf(w, "  err: %s\n", r.Err)
			}
		}
		return nil
	default:
		return fmt.Errorf("unknown --format %q", format)
	}
}
