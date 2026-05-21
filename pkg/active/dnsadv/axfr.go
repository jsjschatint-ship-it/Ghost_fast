package dnsadv

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// axfrCap caps the number of records we keep per AXFR response; beyond this we
// flag the result as truncated. AXFR can return millions of records — we don't
// want to OOM the server on a huge zone.
const axfrCap = 1000

// tryAXFR enumerates the authoritative nameservers for `domain`, then attempts
// a zone transfer against each. Returns one AXFRResult per NS tried.
func tryAXFR(ctx context.Context, domain string, resolvers []string, timeout time.Duration) []*AXFRResult {
	domain = dns.Fqdn(strings.TrimSpace(strings.ToLower(domain)))
	if domain == "." {
		return nil
	}

	// Resolve NS records using stdlib (it's enough — we don't need miekg/dns
	// for plain NS lookups). Try each resolver round-robin until one succeeds.
	nameServers, err := resolveNS(ctx, domain, resolvers, timeout)
	if err != nil {
		return []*AXFRResult{{
			Domain: strings.TrimSuffix(domain, "."),
			Err:    fmt.Sprintf("NS lookup failed: %v", err),
		}}
	}
	if len(nameServers) == 0 {
		return []*AXFRResult{{
			Domain: strings.TrimSuffix(domain, "."),
			Err:    "no NS records returned",
		}}
	}

	out := make([]*AXFRResult, 0, len(nameServers))
	for _, ns := range nameServers {
		select {
		case <-ctx.Done():
			return out
		default:
		}
		out = append(out, axfrFromNS(ctx, domain, ns, timeout))
	}
	return out
}

// axfrFromNS attempts an AXFR transfer of `domain` from a single NS. The NS is
// expected to be a FQDN (`ns1.example.com.`); it is resolved to A/AAAA before
// dialing. Empty NS or unresolvable NS yields an error result, not nil.
func axfrFromNS(ctx context.Context, domain, ns string, timeout time.Duration) *AXFRResult {
	res := &AXFRResult{
		Domain:     strings.TrimSuffix(domain, "."),
		NameServer: ns,
	}
	t0 := time.Now()

	ips, err := net.DefaultResolver.LookupHost(ctx, strings.TrimSuffix(ns, "."))
	if err != nil || len(ips) == 0 {
		res.Err = fmt.Sprintf("resolve NS: %v", err)
		res.DurationMS = time.Since(t0).Milliseconds()
		return res
	}
	addr := net.JoinHostPort(ips[0], "53")
	res.NSAddr = addr

	tr := &dns.Transfer{DialTimeout: timeout, ReadTimeout: timeout, WriteTimeout: timeout}
	m := new(dns.Msg)
	m.SetAxfr(domain)

	env, err := tr.In(m, addr)
	if err != nil {
		res.Err = err.Error()
		res.DurationMS = time.Since(t0).Milliseconds()
		return res
	}

	records := make([]string, 0, 64)
	dropped := false
	for envelope := range env {
		if envelope.Error != nil {
			// Record-level errors usually mean the server refused mid-stream.
			// Preserve any records we got, attach the err, and break.
			res.Err = envelope.Error.Error()
			break
		}
		for _, rr := range envelope.RR {
			if len(records) >= axfrCap {
				dropped = true
				break
			}
			records = append(records, rr.String())
		}
		if dropped {
			break
		}
	}

	res.DurationMS = time.Since(t0).Milliseconds()
	res.Records = records
	res.RecordCount = len(records)
	res.Truncated = dropped
	// AXFR is considered successful when we got at least one SOA/A/CNAME etc.
	// A REFUSED response yields zero records + an Err — that path stays Err'd.
	if len(records) > 0 && res.Err == "" {
		res.Success = true
	}
	return res
}

// resolveNS returns the authoritative nameservers for `domain` using miekg/dns
// against the supplied resolver pool (round-robin). It tries every resolver
// and returns on first non-empty answer. Returns FQDN nameservers (with
// trailing dot stripped by caller as needed).
func resolveNS(ctx context.Context, domain string, resolvers []string, timeout time.Duration) ([]string, error) {
	c := &dns.Client{Net: "udp", Timeout: timeout}
	m := new(dns.Msg)
	m.SetQuestion(domain, dns.TypeNS)
	var lastErr error
	for _, server := range resolvers {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		in, _, err := c.ExchangeContext(ctx, m, server)
		if err != nil {
			lastErr = err
			continue
		}
		if in.Rcode != dns.RcodeSuccess {
			lastErr = fmt.Errorf("%s: rcode %s", server, dns.RcodeToString[in.Rcode])
			continue
		}
		var nss []string
		for _, rr := range in.Answer {
			if ns, ok := rr.(*dns.NS); ok {
				nss = append(nss, ns.Ns)
			}
		}
		if len(nss) > 0 {
			return nss, nil
		}
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, nil
}
