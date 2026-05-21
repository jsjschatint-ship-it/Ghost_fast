package cdninfo

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// bypassLabels are commonly-deployed subdomains that often point straight at
// the origin even when the apex is behind a CDN. Probed (resolved) if
// SkipOriginHunt is false.
var bypassLabels = []string{
	"mail", "smtp", "pop", "pop3", "imap",
	"direct", "origin", "backend", "real",
	"ftp", "sftp",
	"cpanel", "webmail", "admin", "console",
	"dev", "staging", "test", "uat", "internal",
	"old", "legacy",
	"vpn", "remote",
	"ns1", "ns2", "mx", "mx1", "mx2",
}

var spfIncludeRe = regexp.MustCompile(`(?i)include:([A-Za-z0-9_\-.]+)`)

// Detect runs the full fingerprint + origin-hunt for every host in cfg.Hosts.
func Detect(ctx context.Context, cfg Config) *Result {
	cfg.Normalize()
	t0 := time.Now()
	res := &Result{Stats: Stats{VendorCounts: map[string]int{}}}
	if len(cfg.Hosts) == 0 {
		return res
	}

	servers := normalizeServers(cfg.Resolvers)
	dnsClient := &dns.Client{Net: "udp", Timeout: cfg.DNSTimeout}
	httpClient := buildHTTPClient(&cfg)

	reports := make([]*HostReport, len(cfg.Hosts))
	var wg sync.WaitGroup
	gate := make(chan struct{}, cfg.Concurrency)

	for i, host := range cfg.Hosts {
		i, host := i, host
		wg.Add(1)
		gate <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-gate }()
			reports[i] = inspectHost(ctx, host, dnsClient, servers[0], httpClient, &cfg)
		}()
	}
	wg.Wait()

	for _, r := range reports {
		if r == nil {
			continue
		}
		res.Hosts = append(res.Hosts, r)
		res.Stats.HostsScanned++
		if r.HasCDN {
			res.Stats.HostsWithCDN++
		}
		for _, v := range r.Vendors {
			res.Stats.VendorCounts[v.Vendor]++
		}
		res.Stats.OriginCandidates += len(r.OriginCandidates)
	}
	res.DurationMS = time.Since(t0).Milliseconds()
	return res
}

// inspectHost gathers all signals for a single hostname.
func inspectHost(ctx context.Context, host string, dnsClient *dns.Client, server string, httpClient *http.Client, cfg *Config) *HostReport {
	t0 := time.Now()
	host = strings.TrimSpace(strings.ToLower(host))
	host = strings.TrimSuffix(host, ".")
	rep := &HostReport{Host: host}

	// 1) DNS: A + CNAME chain.
	rep.FrontIPs, rep.CNAMEChain = resolveAandCNAMEChain(ctx, dnsClient, server, host)

	// 2) HTTP probe (https first, fall back to http).
	headers, status := probeHeaders(ctx, httpClient, host, cfg.UserAgent)
	rep.ResponseHeaders = headers
	rep.HTTPStatus = status

	// 3) Classify.
	if len(headers) > 0 {
		rep.Vendors = append(rep.Vendors, classifyHeaders(headers)...)
	}
	if len(rep.CNAMEChain) > 0 {
		rep.Vendors = append(rep.Vendors, classifyCNAME(rep.CNAMEChain)...)
	}
	// Dedup vendors (by Vendor+Kind+Source).
	rep.Vendors = dedupHits(rep.Vendors)
	for _, v := range rep.Vendors {
		if v.Kind == "cdn" || v.Kind == "waf" {
			rep.HasCDN = true
			break
		}
	}

	// 4) Origin hunt (only if behind a CDN; otherwise pointless).
	if rep.HasCDN && !cfg.SkipOriginHunt {
		root := registrableRoot(host)
		rep.OriginCandidates = hunt(ctx, dnsClient, server, root, rep.FrontIPs)
		if cfg.DoPassiveDNS {
			rep.OriginCandidates = append(rep.OriginCandidates, passiveOriginCandidates(ctx, httpClient, root, rep.FrontIPs, cfg)...)
			rep.OriginCandidates = dedupOriginCandidates(rep.OriginCandidates)
			sort.Slice(rep.OriginCandidates, func(i, j int) bool {
				if rep.OriginCandidates[i].Source == rep.OriginCandidates[j].Source {
					return rep.OriginCandidates[i].Label < rep.OriginCandidates[j].Label
				}
				return rep.OriginCandidates[i].Source < rep.OriginCandidates[j].Source
			})
		}
	}

	rep.DurationMS = time.Since(t0).Milliseconds()
	return rep
}

// dedupHits removes duplicate VendorHit values.
func dedupHits(in []*VendorHit) []*VendorHit {
	seen := map[string]struct{}{}
	out := in[:0]
	for _, v := range in {
		key := v.Vendor + "|" + v.Kind + "|" + v.Source
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, v)
	}
	return out
}

func dedupOriginCandidates(in []*OriginCandidate) []*OriginCandidate {
	seen := map[string]*OriginCandidate{}
	var out []*OriginCandidate
	for _, c := range in {
		if c == nil {
			continue
		}
		c.Label = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(c.Label)), ".")
		if c.Label == "" {
			continue
		}
		key := c.Source + "|" + c.Label
		if existing, ok := seen[key]; ok {
			for _, ip := range c.IPs {
				existing.IPs = appendUniqueString(existing.IPs, ip)
			}
			if existing.Note == "" {
				existing.Note = c.Note
			}
			continue
		}
		c.IPs = uniqueStrings(c.IPs)
		seen[key] = c
		out = append(out, c)
	}
	return out
}

func uniqueStrings(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

// resolveAandCNAMEChain returns the resolved IP set and the CNAME chain.
func resolveAandCNAMEChain(ctx context.Context, c *dns.Client, server, host string) (ips, chain []string) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), dns.TypeA)
	m.RecursionDesired = true
	in, _, err := c.ExchangeContext(ctx, m, server)
	if err != nil || in == nil {
		return nil, nil
	}
	for _, ans := range in.Answer {
		switch x := ans.(type) {
		case *dns.A:
			ips = append(ips, x.A.String())
		case *dns.CNAME:
			chain = append(chain, strings.TrimSuffix(strings.ToLower(x.Target), "."))
		}
	}
	// Try AAAA too — some CDNs are v6-only on certain pops.
	m6 := new(dns.Msg)
	m6.SetQuestion(dns.Fqdn(host), dns.TypeAAAA)
	if in6, _, err := c.ExchangeContext(ctx, m6, server); err == nil && in6 != nil {
		for _, ans := range in6.Answer {
			if x, ok := ans.(*dns.AAAA); ok {
				ips = append(ips, x.AAAA.String())
			}
		}
	}
	return ips, chain
}

// probeHeaders does HEAD on https://host (then http if that fails) and
// returns a flat map of response headers.
func probeHeaders(ctx context.Context, client *http.Client, host, userAgent string) (map[string]string, int) {
	for _, scheme := range []string{"https", "http"} {
		url := scheme + "://" + host + "/"
		req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
		if err != nil {
			continue
		}
		if userAgent != "" {
			req.Header.Set("User-Agent", userAgent)
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()
		out := make(map[string]string, len(resp.Header))
		for k, v := range resp.Header {
			out[k] = strings.Join(v, ",")
		}
		return out, resp.StatusCode
	}
	return nil, 0
}

// hunt probes "bypass" subdomains + grabs MX/SPF includes. Anything that
// resolves to an IP not in the CDN front IP set becomes an OriginCandidate.
func hunt(ctx context.Context, c *dns.Client, server, root string, frontIPs []string) []*OriginCandidate {
	front := make(map[string]struct{}, len(frontIPs))
	for _, ip := range frontIPs {
		front[ip] = struct{}{}
	}
	var out []*OriginCandidate
	seenLabel := map[string]struct{}{}

	add := func(source, label, note string, ips []string) {
		label = strings.TrimSuffix(strings.ToLower(label), ".")
		if label == "" {
			return
		}
		if _, ok := seenLabel[label]; ok {
			return
		}
		seenLabel[label] = struct{}{}
		// Filter out labels that resolve only to front IPs.
		fresh := make([]string, 0, len(ips))
		for _, ip := range ips {
			if _, ok := front[ip]; !ok {
				fresh = append(fresh, ip)
			}
		}
		if len(fresh) == 0 && len(ips) > 0 {
			return // all front
		}
		ipsOut := fresh
		if len(ipsOut) == 0 {
			ipsOut = ips
		}
		out = append(out, &OriginCandidate{
			Source: source, Label: label, IPs: ipsOut, Note: note,
		})
	}

	// MX records.
	mxs, _ := lookupSimple(ctx, c, server, root, dns.TypeMX)
	for _, mx := range mxs {
		ips, _ := lookupA(ctx, c, server, mx)
		add("mx", mx, "MX server (may host backend / origin)", ips)
	}

	// SPF includes.
	txts, _ := lookupSimple(ctx, c, server, root, dns.TypeTXT)
	for _, t := range txts {
		if !strings.HasPrefix(strings.ToLower(t), "v=spf1") {
			continue
		}
		for _, m := range spfIncludeRe.FindAllStringSubmatch(t, -1) {
			if len(m) < 2 {
				continue
			}
			inc := strings.ToLower(m[1])
			ips, _ := lookupA(ctx, c, server, inc)
			add("spf", inc, "SPF include", ips)
		}
	}

	// Bypass labels.
	for _, lab := range bypassLabels {
		full := lab + "." + root
		ips, _ := lookupA(ctx, c, server, full)
		if len(ips) == 0 {
			continue
		}
		add("bypass_label", full, "Common bypass-CDN sibling", ips)
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Label < out[j].Label })
	return out
}

// lookupSimple returns the string-formatted values for a given record type.
func lookupSimple(ctx context.Context, c *dns.Client, server, name string, qtype uint16) ([]string, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = true
	in, _, err := c.ExchangeContext(ctx, m, server)
	if err != nil || in == nil {
		return nil, err
	}
	var out []string
	for _, ans := range in.Answer {
		switch x := ans.(type) {
		case *dns.MX:
			out = append(out, strings.TrimSuffix(strings.ToLower(x.Mx), "."))
		case *dns.TXT:
			out = append(out, strings.Join(x.Txt, ""))
		}
	}
	return out, nil
}

func lookupA(ctx context.Context, c *dns.Client, server, name string) ([]string, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	m.RecursionDesired = true
	in, _, err := c.ExchangeContext(ctx, m, server)
	if err != nil || in == nil {
		return nil, err
	}
	var out []string
	for _, ans := range in.Answer {
		if x, ok := ans.(*dns.A); ok {
			out = append(out, x.A.String())
		}
	}
	return out, nil
}

// registrableRoot is a best-effort eTLD+1 lookup. We use a simple two-label
// fallback for unknown TLDs since pulling in publicsuffix is overkill for
// this use case (cdninfo is a hint, not a registrar).
func registrableRoot(host string) string {
	parts := strings.Split(host, ".")
	if len(parts) <= 2 {
		return host
	}
	// Multi-level country TLDs (e.g. com.cn, co.uk).
	last2 := parts[len(parts)-2] + "." + parts[len(parts)-1]
	switch last2 {
	case "com.cn", "net.cn", "org.cn", "edu.cn", "gov.cn",
		"co.uk", "ac.uk", "org.uk", "gov.uk",
		"co.jp", "ne.jp", "or.jp",
		"com.au", "net.au", "org.au":
		if len(parts) >= 3 {
			return parts[len(parts)-3] + "." + last2
		}
	}
	return parts[len(parts)-2] + "." + parts[len(parts)-1]
}

func buildHTTPClient(cfg *Config) *http.Client {
	return &http.Client{
		Timeout: cfg.HTTPTimeout,
		Transport: &http.Transport{
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
			ResponseHeaderTimeout: cfg.HTTPTimeout,
		},
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

func normalizeServers(in []string) []string {
	if len(in) == 0 {
		return []string{"1.1.1.1:53", "8.8.8.8:53"}
	}
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(s); err != nil {
			s = s + ":53"
		}
		out = append(out, s)
	}
	if len(out) == 0 {
		return []string{"1.1.1.1:53"}
	}
	return out
}
