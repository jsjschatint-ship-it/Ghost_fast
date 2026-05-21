package asn

import (
	"context"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var asnNumRe = regexp.MustCompile(`(?i)^as(\d+)$`)
var pureNumRe = regexp.MustCompile(`^\d+$`)

// Lookup runs the full ASN expansion for cfg.Inputs.
func Lookup(ctx context.Context, cfg Config) *Result {
	cfg.Normalize()
	t0 := time.Now()
	res := &Result{}

	httpClient := &http.Client{Timeout: cfg.HTTPTimeout}
	bgp := newBGPViewClient(cfg.BGPViewBase, cfg.UserAgent, httpClient)

	// Stage 1: classify inputs.
	var (
		ips      []string
		asnNums  []int
		orgTerms []string
	)
	for _, in := range cfg.Inputs {
		in = strings.TrimSpace(in)
		if in == "" {
			continue
		}
		// ASN form.
		if m := asnNumRe.FindStringSubmatch(in); len(m) >= 2 {
			if n, err := strconv.Atoi(m[1]); err == nil {
				asnNums = append(asnNums, n)
				continue
			}
		}
		if pureNumRe.MatchString(in) {
			if n, err := strconv.Atoi(in); err == nil && n > 0 && n < 4294967295 {
				asnNums = append(asnNums, n)
				continue
			}
		}
		// IP form.
		if net.ParseIP(in) != nil {
			ips = append(ips, in)
			continue
		}
		// Hostname form.
		if looksLikeHost(in) {
			if cfg.ResolveHostnames || !cfg.ResolveHostnames /* default to resolve */ {
				resolved, _ := net.DefaultResolver.LookupIPAddr(ctx, in)
				if len(resolved) > 0 {
					for _, r := range resolved {
						ips = append(ips, r.IP.String())
					}
					continue
				}
			}
		}
		// Otherwise treat as org-search term.
		orgTerms = append(orgTerms, in)
	}
	res.Stats.Inputs = len(cfg.Inputs)

	// Stage 2: resolve IPs → ASNs (bgpview /ip).
	var (
		mu       sync.Mutex
		mappings []*IPMapping
		asnSet   = map[int]struct{}{}
		wg       sync.WaitGroup
		gate     = make(chan struct{}, cfg.Concurrency)
	)
	for _, ip := range ips {
		ip := ip
		wg.Add(1)
		gate <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-gate }()
			mapping, theseASNs, err := bgp.ipToASNs(ctx, ip)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				mappings = append(mappings, &IPMapping{IP: ip, Source: "bgpview", Err: err.Error()})
				return
			}
			mapping.Input = ip
			mappings = append(mappings, mapping)
			for _, a := range theseASNs {
				asnSet[a] = struct{}{}
			}
		}()
	}
	wg.Wait()
	res.IPMappings = mappings

	// Stage 3: org search → ASN.
	for _, term := range orgTerms {
		theseASNs, err := bgp.searchOrg(ctx, term)
		if err != nil {
			continue
		}
		for _, a := range theseASNs {
			asnSet[a] = struct{}{}
		}
	}

	// Add explicit asnNums.
	for _, a := range asnNums {
		asnSet[a] = struct{}{}
	}

	// Cap ASN count.
	allASNs := make([]int, 0, len(asnSet))
	for a := range asnSet {
		allASNs = append(allASNs, a)
	}
	sort.Ints(allASNs)
	if cfg.MaxASNs > 0 && len(allASNs) > cfg.MaxASNs {
		allASNs = allASNs[:cfg.MaxASNs]
	}

	// Stage 4: ASN detail + prefix expansion (parallel).
	wg = sync.WaitGroup{}
	infos := make([]*ASNInfo, len(allASNs))
	prefixGroups := make([][]*Prefix, len(allASNs))
	for i, num := range allASNs {
		i, num := i, num
		wg.Add(1)
		gate <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-gate }()
			if info, err := bgp.asnDetail(ctx, num); err == nil && info != nil {
				infos[i] = info
			} else {
				infos[i] = &ASNInfo{ASN: num}
			}
			if pfx, err := bgp.asnPrefixes(ctx, num, !cfg.SkipIPv6, cfg.MaxPrefixesPerASN); err == nil {
				prefixGroups[i] = pfx
			}
		}()
	}
	wg.Wait()

	for _, inf := range infos {
		if inf != nil {
			res.ASNs = append(res.ASNs, inf)
		}
	}
	dedupP := map[string]struct{}{}
	for _, group := range prefixGroups {
		for _, p := range group {
			if _, ok := dedupP[p.CIDR]; ok {
				continue
			}
			dedupP[p.CIDR] = struct{}{}
			res.Prefixes = append(res.Prefixes, p)
			if p.Family == 4 {
				res.Stats.IPv4Prefixes++
			} else {
				res.Stats.IPv6Prefixes++
			}
		}
	}
	sort.Slice(res.Prefixes, func(i, j int) bool {
		if res.Prefixes[i].Family != res.Prefixes[j].Family {
			return res.Prefixes[i].Family < res.Prefixes[j].Family
		}
		return res.Prefixes[i].CIDR < res.Prefixes[j].CIDR
	})
	res.Stats.ASNs = len(res.ASNs)
	res.DurationMS = time.Since(t0).Milliseconds()
	return res
}

// looksLikeHost is a coarse heuristic: contains a "." and is not a CIDR /
// pure number. Used to classify ambiguous inputs.
func looksLikeHost(s string) bool {
	if strings.Contains(s, "/") || strings.Contains(s, " ") {
		return false
	}
	return strings.Contains(s, ".")
}
