package whoisrdap

import (
	"context"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Lookup runs RDAP + WHOIS for every Inputs entry and returns a merged Result.
func Lookup(ctx context.Context, cfg Config) *Result {
	cfg.Normalize()
	t0 := time.Now()
	res := &Result{}
	if len(cfg.Inputs) == 0 {
		return res
	}

	httpClient := &http.Client{Timeout: cfg.HTTPTimeout}

	records := make([]*Record, len(cfg.Inputs))
	var wg sync.WaitGroup
	gate := make(chan struct{}, cfg.Concurrency)

	for i, in := range cfg.Inputs {
		i, in := i, in
		wg.Add(1)
		gate <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-gate }()
			records[i] = lookupOne(ctx, httpClient, in, &cfg)
		}()
	}
	wg.Wait()

	emails := map[string]struct{}{}
	for _, r := range records {
		if r == nil {
			continue
		}
		if cfg.DoReverseWHOIS && r.Kind == "domain" {
			pivots := reverseWhoisPivots(r)
			seenSibling := map[string]struct{}{}
			for _, pivot := range pivots {
				if len(r.SiblingDomains) >= cfg.MaxSiblingDomains {
					break
				}
				for _, sib := range reverseWhoisSiblings(ctx, httpClient, pivot, &cfg) {
					if sib == nil || sib.Domain == "" || strings.EqualFold(sib.Domain, r.Domain) {
						continue
					}
					if _, ok := seenSibling[sib.Domain]; ok {
						continue
					}
					seenSibling[sib.Domain] = struct{}{}
					r.SiblingDomains = append(r.SiblingDomains, sib)
					if len(r.SiblingDomains) >= cfg.MaxSiblingDomains {
						break
					}
				}
			}
		}
		res.Records = append(res.Records, r)
		res.Stats.Inputs++
		hadSource := false
		for _, s := range r.Sources {
			switch s {
			case "rdap":
				res.Stats.RDAPOK++
				hadSource = true
			case "whois":
				res.Stats.WHOISOK++
				hadSource = true
			}
		}
		if !hadSource {
			res.Stats.Failed++
		}
		for _, c := range r.Contacts {
			if c != nil && c.Email != "" {
				emails[c.Email] = struct{}{}
			}
		}
		res.Stats.SiblingDomains += len(r.SiblingDomains)
	}
	res.Stats.UniqueEmails = len(emails)
	res.DurationMS = time.Since(t0).Milliseconds()
	return res
}

func lookupOne(ctx context.Context, client *http.Client, input string, cfg *Config) *Record {
	t0 := time.Now()
	in := strings.TrimSpace(input)
	rec := &Record{Input: in, Raw: map[string]string{}}
	if in == "" {
		rec.Err = "empty input"
		return rec
	}

	if net.ParseIP(in) != nil {
		rec.Kind = "ip"
	} else {
		rec.Kind = "domain"
		rec.Domain = strings.ToLower(strings.TrimSuffix(in, "."))
	}

	// Stage 1: RDAP.
	if cfg.DoRDAP {
		if rec.Kind == "domain" {
			d, raw, err := rdapForDomain(ctx, client, cfg.UserAgent, rec.Domain)
			if err == nil && d != nil {
				applyRDAPDomain(rec, d)
				if len(raw) > 0 {
					rec.Raw["rdap_json"] = string(raw)
				}
				rec.Sources = append(rec.Sources, "rdap")
			} else if err != nil {
				rec.Err = err.Error()
			}
		} else {
			n, raw, err := rdapForIP(ctx, client, cfg.UserAgent, in)
			if err == nil && n != nil {
				applyRDAPIP(rec, n)
				if len(raw) > 0 {
					rec.Raw["rdap_json"] = string(raw)
				}
				rec.Sources = append(rec.Sources, "rdap")
			} else if err != nil {
				rec.Err = err.Error()
			}
		}
	}

	// Stage 2: WHOIS (fills gaps RDAP missed).
	if cfg.DoWHOIS {
		server, body, err := whoisFor(ctx, in, cfg.WHOISTimeout)
		if err == nil && len(body) > 0 {
			rec.WHOISServer = server
			rec.Raw["whois_text"] = body
			fields := parseWhoisFields(body)
			if rec.Registrar == "" && fields.Registrar != "" {
				rec.Registrar = fields.Registrar
			}
			if rec.RegistrarURL == "" && fields.RegistrarURL != "" {
				rec.RegistrarURL = fields.RegistrarURL
			}
			if rec.CreatedAt == "" {
				rec.CreatedAt = fields.Created
			}
			if rec.UpdatedAt == "" {
				rec.UpdatedAt = fields.Updated
			}
			if rec.ExpiresAt == "" {
				rec.ExpiresAt = fields.Expires
			}
			for _, ns := range fields.Nameservers {
				rec.Nameservers = appendUnique(rec.Nameservers, ns)
			}
			for _, st := range fields.Status {
				rec.Status = appendUnique(rec.Status, st)
			}
			// Synthesise registrant contact if RDAP didn't supply one.
			if fields.RegistrantEmail != "" || fields.RegistrantName != "" || fields.RegistrantOrg != "" {
				exists := false
				for _, c := range rec.Contacts {
					if c != nil && c.Role == "registrant" {
						exists = true
						break
					}
				}
				if !exists {
					rec.Contacts = append(rec.Contacts, &Contact{
						Role:         "registrant",
						Name:         fields.RegistrantName,
						Organization: fields.RegistrantOrg,
						Email:        fields.RegistrantEmail,
						Country:      fields.RegistrantCountry,
					})
				}
			}
			if fields.AdminEmail != "" {
				rec.Contacts = append(rec.Contacts, &Contact{Role: "admin", Email: fields.AdminEmail})
			}
			if fields.TechEmail != "" {
				rec.Contacts = append(rec.Contacts, &Contact{Role: "tech", Email: fields.TechEmail})
			}
			rec.Sources = append(rec.Sources, "whois")
			rec.Err = "" // we got something useful; suppress the RDAP error
		}
	}

	rec.DurationMS = time.Since(t0).Milliseconds()
	return rec
}

func reverseWhoisPivots(r *Record) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(v string) {
		v = strings.TrimSpace(strings.ToLower(v))
		if v == "" {
			return
		}
		if _, ok := seen[v]; ok {
			return
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	for _, c := range r.Contacts {
		if c == nil {
			continue
		}
		add(c.Email)
		add(c.Organization)
		if c.Role == "registrant" {
			add(c.Name)
		}
	}
	return out
}
