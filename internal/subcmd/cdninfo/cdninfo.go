// Package cdninfo is the `ghost cdninfo` subcommand.
package cdninfo

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/wgpsec/ENScan/pkg/active/cdninfo"
)

type flags struct {
	hosts             []string
	hostFile          string
	resolvers         []string
	httpTimeoutSec    int
	dnsTimeoutSec     int
	concurrency       int
	skipOrigin        bool
	passiveDNS        bool
	passiveSources    []string
	maxPassive        int
	securityTrailsKey string
	virusTotalKey     string
	output            string
	format            string
}

// New constructs the cobra subcommand.
func New() *cobra.Command {
	f := &flags{}
	cmd := &cobra.Command{
		Use:   "cdninfo",
		Short: "CDN/WAF 指纹 + 源站 IP 发现（MX/SPF/常见 bypass 标签）",
		Long: `ghost cdninfo 对每个 host 抓响应头 + 解析 CNAME 链，对照 20+ CDN/WAF 指纹库
判定厂商。若识别为 CDN，进一步通过 MX、SPF include、常见 bypass 子域（mail、
direct、origin、cpanel 等）寻找可能的源站 IP。`,
		RunE: f.run,
	}
	cmd.Flags().StringSliceVarP(&f.hosts, "host", "H", nil, "目标 host（可重复或逗号分隔）")
	cmd.Flags().StringVar(&f.hostFile, "host-file", "", "host 文件，一行一个")
	cmd.Flags().StringSliceVar(&f.resolvers, "resolver", nil, "DNS 解析器")
	cmd.Flags().IntVar(&f.httpTimeoutSec, "http-timeout", 10, "HTTP 超时（秒）")
	cmd.Flags().IntVar(&f.dnsTimeoutSec, "dns-timeout", 4, "DNS 超时（秒）")
	cmd.Flags().IntVar(&f.concurrency, "concurrency", 8, "并发数")
	cmd.Flags().BoolVar(&f.skipOrigin, "skip-origin", false, "跳过源站 hunt 阶段")
	cmd.Flags().BoolVar(&f.passiveDNS, "passive-dns", false, "启用历史 DNS / Passive DNS 源站候选（SecurityTrails/VirusTotal/ThreatMiner/HackerTarget）")
	cmd.Flags().StringSliceVar(&f.passiveSources, "passive-source", nil, "Passive DNS 数据源：securitytrails,virustotal,threatminer,hackertarget")
	cmd.Flags().IntVar(&f.maxPassive, "max-passive", 100, "最多保留 Passive DNS 候选")
	cmd.Flags().StringVar(&f.securityTrailsKey, "securitytrails-key", "", "SecurityTrails API key（可选）")
	cmd.Flags().StringVar(&f.virusTotalKey, "virustotal-key", "", "VirusTotal API key（可选）")
	cmd.Flags().StringVarP(&f.output, "output", "o", "", "输出文件（默认 stdout）")
	cmd.Flags().StringVar(&f.format, "format", "json", "输出格式：json|text")
	return cmd
}

func (f *flags) run(cmd *cobra.Command, args []string) error {
	hosts := collect(f.hosts, f.hostFile)
	if len(hosts) == 0 {
		return fmt.Errorf("must provide --host or --host-file")
	}
	cfg := cdninfo.Config{
		Hosts:             hosts,
		Resolvers:         f.resolvers,
		HTTPTimeout:       time.Duration(f.httpTimeoutSec) * time.Second,
		DNSTimeout:        time.Duration(f.dnsTimeoutSec) * time.Second,
		Concurrency:       f.concurrency,
		SkipOriginHunt:    f.skipOrigin,
		DoPassiveDNS:      f.passiveDNS,
		PassiveSources:    f.passiveSources,
		MaxPassiveRecords: f.maxPassive,
		SecurityTrailsKey: f.securityTrailsKey,
		VirusTotalKey:     f.virusTotalKey,
	}
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	res := cdninfo.Detect(ctx, cfg)
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
		s = strings.TrimPrefix(strings.TrimPrefix(s, "https://"), "http://")
		if i := strings.IndexByte(s, '/'); i >= 0 {
			s = s[:i]
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

func emit(out, format string, res *cdninfo.Result) error {
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
		fmt.Fprintf(w, "CDN/WAF scan: %d hosts (%d behind CDN) / %dms\n", res.Stats.HostsScanned, res.Stats.HostsWithCDN, res.DurationMS)
		for _, h := range res.Hosts {
			fmt.Fprintf(w, "=== %s ===\n", h.Host)
			if len(h.Vendors) == 0 {
				fmt.Fprintln(w, "  no vendor detected")
			}
			for _, v := range h.Vendors {
				fmt.Fprintf(w, "  [%s/%s] %s — %s\n", v.Kind, v.Source, v.Vendor, v.Evidence)
			}
			if len(h.OriginCandidates) > 0 {
				fmt.Fprintln(w, "  --- origin candidates ---")
				for _, oc := range h.OriginCandidates {
					fmt.Fprintf(w, "    [%s] %s → %v   %s\n", oc.Source, oc.Label, oc.IPs, oc.Note)
				}
			}
		}
		return nil
	default:
		return fmt.Errorf("unknown --format %q", format)
	}
}
