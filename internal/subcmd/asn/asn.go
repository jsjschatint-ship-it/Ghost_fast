// Package asn is the `ghost asn` subcommand.
package asn

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/wgpsec/ENScan/pkg/active/asn"
)

type flags struct {
	inputs      []string
	inputFile   string
	skipIPv6    bool
	maxASNs     int
	maxPrefixes int
	timeoutSec  int
	concurrency int
	bgpviewBase string
	output      string
	format      string
}

// New constructs the cobra subcommand.
func New() *cobra.Command {
	f := &flags{}
	cmd := &cobra.Command{
		Use:   "asn",
		Short: "BGP/ASN 网段扩展（IP/host/AS号/组织名 → 全部 CIDR）",
		Long: `ghost asn 把 IP / 主机名 / "AS13335" / 组织名当输入，通过 bgpview.io
查出 ASN，再展开成所有 announced 前缀。输出可直接喂回 portscan / httpx。`,
		RunE: f.run,
	}
	cmd.Flags().StringSliceVarP(&f.inputs, "input", "i", nil, "IP / host / AS<num> / 组织名（可重复或逗号分隔）")
	cmd.Flags().StringVar(&f.inputFile, "input-file", "", "输入文件，一行一个")
	cmd.Flags().BoolVar(&f.skipIPv6, "skip-ipv6", false, "丢弃 IPv6 前缀")
	cmd.Flags().IntVar(&f.maxASNs, "max-asns", 50, "最多展开的 ASN 数")
	cmd.Flags().IntVar(&f.maxPrefixes, "max-prefixes", 2000, "每 ASN 最多前缀数")
	cmd.Flags().IntVar(&f.timeoutSec, "timeout", 15, "上游 API 超时（秒）")
	cmd.Flags().IntVar(&f.concurrency, "concurrency", 4, "并发数")
	cmd.Flags().StringVar(&f.bgpviewBase, "bgpview", "", "bgpview.io API 根（默认 https://api.bgpview.io）")
	cmd.Flags().StringVarP(&f.output, "output", "o", "", "输出文件（默认 stdout）")
	cmd.Flags().StringVar(&f.format, "format", "json", "输出格式：json|text|cidr")
	return cmd
}

func (f *flags) run(cmd *cobra.Command, args []string) error {
	inputs := collect(f.inputs, f.inputFile)
	if len(inputs) == 0 {
		return fmt.Errorf("must provide --input or --input-file")
	}
	cfg := asn.Config{
		Inputs:            inputs,
		ResolveHostnames:  true,
		SkipIPv6:          f.skipIPv6,
		MaxASNs:           f.maxASNs,
		MaxPrefixesPerASN: f.maxPrefixes,
		HTTPTimeout:       time.Duration(f.timeoutSec) * time.Second,
		Concurrency:       f.concurrency,
		BGPViewBase:       f.bgpviewBase,
	}
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	res := asn.Lookup(ctx, cfg)
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

func emit(out, format string, res *asn.Result) error {
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
		fmt.Fprintf(w, "ASN expansion: %d inputs → %d ASNs / %d v4 / %d v6 (%dms)\n",
			res.Stats.Inputs, res.Stats.ASNs, res.Stats.IPv4Prefixes, res.Stats.IPv6Prefixes, res.DurationMS)
		for _, a := range res.ASNs {
			fmt.Fprintf(w, "  AS%d  %s — %s [%s]\n", a.ASN, a.Name, a.Description, a.Country)
		}
		fmt.Fprintln(w, "  --- prefixes ---")
		for _, p := range res.Prefixes {
			fmt.Fprintf(w, "    %s  v%d  %s\n", p.CIDR, p.Family, p.Description)
		}
		return nil
	case "cidr":
		// CIDR-only: pipe-into-portscan friendly output.
		for _, p := range res.Prefixes {
			fmt.Fprintln(w, p.CIDR)
		}
		return nil
	default:
		return fmt.Errorf("unknown --format %q", format)
	}
}
