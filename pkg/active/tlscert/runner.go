package tlscert

import (
	"context"
	"crypto/tls"
	"net/http"
	"sort"
	"sync"
	"time"
)

// Run executes the configured stages and returns a unified Result.
func Run(ctx context.Context, cfg Config) *Result {
	cfg.Normalize()
	t0 := time.Now()
	res := &Result{}

	// Default toggles: live TLS + favicon ON, crt.sh OFF (rate-limited).
	if !cfg.DoLiveTLS && !cfg.DoCrtSh && !cfg.DoFavicon {
		cfg.DoLiveTLS = true
		cfg.DoFavicon = true
	}

	// Shared HTTP client for crt.sh + favicons.
	httpClient := &http.Client{
		Timeout: cfg.HTTPTimeout,
		Transport: &http.Transport{
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
			ResponseHeaderTimeout: cfg.HTTPTimeout,
		},
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	var wg sync.WaitGroup
	gate := make(chan struct{}, cfg.Concurrency)

	// ---- Stage 1: live TLS ----
	if cfg.DoLiveTLS && len(cfg.Targets) > 0 {
		certs := make([]*CertInfo, len(cfg.Targets))
		for i, tgt := range cfg.Targets {
			i, tgt := i, tgt
			wg.Add(1)
			gate <- struct{}{}
			go func() {
				defer wg.Done()
				defer func() { <-gate }()
				certs[i] = fetchCert(ctx, tgt, cfg.TLSTimeout)
			}()
		}
		wg.Wait()
		res.Certs = certs
	}

	// ---- Stage 2: favicon hashes ----
	if cfg.DoFavicon {
		urls := cfg.FaviconURLs
		if len(urls) == 0 && len(cfg.Targets) > 0 {
			// Synthesise https://<target>/favicon.ico from each target.
			urls = make([]string, 0, len(cfg.Targets))
			for _, t := range cfg.Targets {
				host, port := splitHostPort(t)
				scheme := "https"
				if port == "80" {
					scheme = "http"
				}
				if port == "443" || port == "" {
					urls = append(urls, scheme+"://"+host+"/favicon.ico")
				} else {
					urls = append(urls, scheme+"://"+host+":"+port+"/favicon.ico")
				}
			}
		}
		favs := make([]*FaviconHash, len(urls))
		for i, u := range urls {
			i, u := i, u
			wg.Add(1)
			gate <- struct{}{}
			go func() {
				defer wg.Done()
				defer func() { <-gate }()
				favs[i] = fetchFavicon(ctx, httpClient, u, cfg.UserAgent)
			}()
		}
		wg.Wait()
		res.Favicons = favs
	}

	// ---- Stage 3: crt.sh ----
	if cfg.DoCrtSh && len(cfg.CTLogDomains) > 0 {
		// crt.sh is heavily rate-limited — keep concurrency very low.
		ctGate := make(chan struct{}, 2)
		queries := make([]*CTQuery, len(cfg.CTLogDomains))
		for i, d := range cfg.CTLogDomains {
			i, d := i, d
			wg.Add(1)
			ctGate <- struct{}{}
			go func() {
				defer wg.Done()
				defer func() { <-ctGate }()
				queries[i] = queryCrtSh(ctx, httpClient, d, cfg.CrtShMaxRows, cfg.UserAgent)
			}()
		}
		wg.Wait()
		res.CTQueries = queries
	}

	// ---- Aggregate stats ----
	for _, c := range res.Certs {
		if c == nil {
			continue
		}
		if c.Err == "" && c.SHA256 != "" {
			res.Stats.CertsOK++
		} else {
			res.Stats.CertsErr++
		}
	}
	uniqueCT := map[string]struct{}{}
	for _, q := range res.CTQueries {
		if q == nil {
			continue
		}
		res.Stats.CTRows += len(q.Rows)
		for _, n := range q.UniqueNames {
			uniqueCT[n] = struct{}{}
		}
	}
	res.Stats.CTUniqueNames = len(uniqueCT)
	for _, f := range res.Favicons {
		if f != nil && f.Err == "" && f.MMH3 != 0 {
			res.Stats.FaviconsHashed++
		}
	}

	// Sort favicons by URL + certs by Target for deterministic output.
	sort.Slice(res.Certs, func(i, j int) bool {
		if res.Certs[i] == nil {
			return false
		}
		if res.Certs[j] == nil {
			return true
		}
		return res.Certs[i].Target < res.Certs[j].Target
	})
	sort.Slice(res.Favicons, func(i, j int) bool {
		if res.Favicons[i] == nil {
			return false
		}
		if res.Favicons[j] == nil {
			return true
		}
		return res.Favicons[i].URL < res.Favicons[j].URL
	})
	res.DurationMS = time.Since(t0).Milliseconds()
	return res
}
