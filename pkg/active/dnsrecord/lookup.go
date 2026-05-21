package dnsrecord

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// defaultDKIMSelectors covers the highest-hit-rate selectors used by major
// SaaS senders. The probe is just A/CNAME lookup at <sel>._domainkey.<domain>.
var defaultDKIMSelectors = []string{
	// generic / DIY
	"default", "dkim", "mail", "key1", "key2", "selector1", "selector2",
	// Google Workspace
	"google",
	// Microsoft 365
	"selector1", "selector2",
	// AWS SES (one per region; we'll just probe the common ones)
	"amazonses",
	// SendGrid / Mailgun / Mailchimp
	"s1", "s2", "k1", "k2", "smtpapi",
	// Postmark / Mandrill
	"pm", "mandrill",
	// 国内
	"aliyun", "ali", "dingtalk", "feishu", "lark",
}

// defaultSRVLabels covers commonly-deployed services. Pretty noisy, hence
// gated by SkipSRV.
var defaultSRVLabels = []string{
	"_sip._tcp", "_sip._udp", "_sips._tcp",
	"_xmpp-server._tcp", "_xmpp-client._tcp",
	"_imap._tcp", "_imaps._tcp", "_pop3._tcp", "_pop3s._tcp",
	"_smtp._tcp", "_submission._tcp",
	"_ldap._tcp", "_kerberos._tcp",
	"_autodiscover._tcp", "_caldav._tcp", "_carddav._tcp",
	"_minecraft._tcp",
}

// Lookup runs the full enumeration for one domain.
func Lookup(ctx context.Context, domain string, cfg Config) *Result {
	cfg.Normalize()
	t0 := time.Now()
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	res := &Result{Domain: domain, Stats: Stats{ByType: map[string]int{}}}
	if domain == "" {
		return res
	}

	client := &dns.Client{Net: "udp", Timeout: cfg.Timeout}
	servers := normalizeServers(cfg.Resolvers)

	type task struct {
		Name  string
		Qtype uint16
		Label string
	}
	tasks := []task{
		{domain, dns.TypeA, "A"},
		{domain, dns.TypeAAAA, "AAAA"},
		{domain, dns.TypeMX, "MX"},
		{domain, dns.TypeTXT, "TXT"},
		{domain, dns.TypeSOA, "SOA"},
		{domain, dns.TypeNS, "NS"},
		{domain, dns.TypeCAA, "CAA"},
		{domain, dns.TypeCNAME, "CNAME"},
		// DMARC lives at _dmarc.<domain> as TXT.
		{"_dmarc." + domain, dns.TypeTXT, "DMARC"},
	}
	if !cfg.SkipDKIM {
		sels := cfg.DKIMSelectors
		if len(sels) == 0 {
			sels = defaultDKIMSelectors
		}
		seen := map[string]struct{}{}
		for _, sel := range sels {
			sel = strings.TrimSpace(sel)
			if sel == "" {
				continue
			}
			if _, ok := seen[sel]; ok {
				continue
			}
			seen[sel] = struct{}{}
			tasks = append(tasks, task{sel + "._domainkey." + domain, dns.TypeTXT, "DKIM"})
		}
	}
	if !cfg.SkipSRV {
		labels := cfg.SRVLabels
		if len(labels) == 0 {
			labels = defaultSRVLabels
		}
		for _, lab := range labels {
			tasks = append(tasks, task{lab + "." + domain, dns.TypeSRV, "SRV"})
		}
	}

	var (
		mu      sync.Mutex
		rrs     []*RR
		wg      sync.WaitGroup
		gate    = make(chan struct{}, cfg.Concurrency)
		serverI = 0
		serverM sync.Mutex
	)
	pickServer := func() string {
		serverM.Lock()
		defer serverM.Unlock()
		s := servers[serverI%len(servers)]
		serverI++
		return s
	}

	for _, tk := range tasks {
		select {
		case <-ctx.Done():
			break
		default:
		}
		tk := tk
		wg.Add(1)
		gate <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-gate }()
			answers := query(ctx, client, pickServer(), tk.Name, tk.Qtype)
			converted := convertRRs(answers, tk.Label)
			if len(converted) == 0 {
				return
			}
			mu.Lock()
			rrs = append(rrs, converted...)
			mu.Unlock()
		}()
	}
	wg.Wait()

	// Deterministic ordering: by Type, then by Name, then by Value.
	sort.Slice(rrs, func(i, j int) bool {
		if rrs[i].Type != rrs[j].Type {
			return rrs[i].Type < rrs[j].Type
		}
		if rrs[i].Name != rrs[j].Name {
			return rrs[i].Name < rrs[j].Name
		}
		return rrs[i].Value < rrs[j].Value
	})
	res.Records = rrs

	// Stats.
	res.Stats.Total = len(rrs)
	for _, r := range rrs {
		res.Stats.ByType[r.Type]++
	}

	// Classify TXT/DMARC/DKIM/SPF.
	tokens := map[string]*TokenMatch{}
	for _, r := range rrs {
		if r.Type != "TXT" && r.Type != "DMARC" && r.Type != "DKIM" {
			continue
		}
		for _, m := range classifyTXT(r.Value) {
			key := m.Provider + "|" + m.Type + "|" + m.Value
			if _, ok := tokens[key]; !ok {
				tokens[key] = m
			}
		}
	}
	res.Tokens = make([]*TokenMatch, 0, len(tokens))
	for _, m := range tokens {
		res.Tokens = append(res.Tokens, m)
	}
	sort.Slice(res.Tokens, func(i, j int) bool {
		if res.Tokens[i].Provider != res.Tokens[j].Provider {
			return res.Tokens[i].Provider < res.Tokens[j].Provider
		}
		return res.Tokens[i].Type < res.Tokens[j].Type
	})
	res.Stats.TokensCount = len(res.Tokens)

	// Email inferences.
	res.Email = deriveEmail(rrs)

	res.DurationMS = time.Since(t0).Milliseconds()
	return res
}

// query sends one DNS request; returns the answer RRs (empty on error).
func query(ctx context.Context, client *dns.Client, server, name string, qtype uint16) []dns.RR {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = true
	deadline, hasDeadline := ctx.Deadline()
	if hasDeadline {
		client.Timeout = time.Until(deadline)
	}
	in, _, err := client.ExchangeContext(ctx, m, server)
	if err != nil || in == nil {
		return nil
	}
	return in.Answer
}

// convertRRs converts dns.RR values into our flat RR shape; label is the
// logical record category used in output (TXT vs DMARC vs DKIM differ only
// by query name, not by wire-format).
func convertRRs(in []dns.RR, label string) []*RR {
	var out []*RR
	for _, r := range in {
		if r == nil {
			continue
		}
		hdr := r.Header()
		name := strings.TrimSuffix(strings.ToLower(hdr.Name), ".")
		switch x := r.(type) {
		case *dns.A:
			out = append(out, &RR{Type: label, Name: name, Value: x.A.String()})
		case *dns.AAAA:
			out = append(out, &RR{Type: label, Name: name, Value: x.AAAA.String()})
		case *dns.MX:
			out = append(out, &RR{Type: "MX", Name: name, Value: trimDot(x.Mx), Priority: x.Preference})
		case *dns.TXT:
			out = append(out, &RR{Type: label, Name: name, Value: strings.Join(x.Txt, "")})
		case *dns.SOA:
			out = append(out, &RR{Type: "SOA", Name: name, Value: fmt.Sprintf("%s %s %d", trimDot(x.Ns), trimDot(x.Mbox), x.Serial)})
		case *dns.NS:
			out = append(out, &RR{Type: "NS", Name: name, Value: trimDot(x.Ns)})
		case *dns.CAA:
			out = append(out, &RR{Type: "CAA", Name: name, Value: fmt.Sprintf("%d %s %q", x.Flag, x.Tag, x.Value), Priority: uint16(x.Flag)})
		case *dns.CNAME:
			out = append(out, &RR{Type: label, Name: name, Value: trimDot(x.Target)})
		case *dns.SRV:
			out = append(out, &RR{Type: "SRV", Name: name, Value: trimDot(x.Target), Priority: x.Priority, Weight: x.Weight, Port: x.Port})
		}
	}
	return out
}

func trimDot(s string) string { return strings.TrimSuffix(strings.ToLower(s), ".") }

// normalizeServers ensures every server has a port. Falls back to the OS
// default if empty.
func normalizeServers(in []string) []string {
	if len(in) == 0 {
		// Fall back to a small fixed list — we ship miekg/dns, not the OS
		// resolver, so we always need explicit servers.
		return []string{"1.1.1.1:53", "8.8.8.8:53", "223.5.5.5:53"}
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

var spfIncludeRe = regexp.MustCompile(`(?i)include:([A-Za-z0-9_\-.]+)`)
var dmarcPolicyRe = regexp.MustCompile(`(?i)\bp=([a-z]+)\b`)

// deriveEmail synthesises the Email inference block from the flat RR list.
func deriveEmail(rrs []*RR) Email {
	var e Email
	for _, r := range rrs {
		switch r.Type {
		case "MX":
			e.MXProviders = appendUnique(e.MXProviders, r.Value)
		case "TXT":
			if strings.HasPrefix(strings.ToLower(r.Value), "v=spf1") {
				e.SPF = r.Value
				for _, m := range spfIncludeRe.FindAllStringSubmatch(r.Value, -1) {
					if len(m) >= 2 {
						e.SPFIncludes = appendUnique(e.SPFIncludes, m[1])
					}
				}
			}
		case "DMARC":
			if strings.HasPrefix(strings.ToLower(r.Value), "v=dmarc1") {
				e.DMARC = r.Value
				if m := dmarcPolicyRe.FindStringSubmatch(r.Value); len(m) >= 2 {
					e.DMARCPolicy = strings.ToLower(m[1])
				}
			}
		}
	}
	sort.Strings(e.MXProviders)
	sort.Strings(e.SPFIncludes)
	return e
}

func appendUnique(in []string, v string) []string {
	v = strings.TrimSpace(strings.ToLower(v))
	if v == "" {
		return in
	}
	for _, x := range in {
		if x == v {
			return in
		}
	}
	return append(in, v)
}
