package asn

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeBGPView mocks the bgpview.io endpoints we use.
func fakeBGPView(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/ip/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status":"ok","data":{"ip":"1.1.1.1","prefixes":[{"prefix":"1.1.1.0/24","ip_version":4,"asn":{"asn":13335,"name":"CLOUDFLARENET","description":"Cloudflare, Inc.","country_code":"US"},"name":"APNIC-LABS","description":"APNIC and Cloudflare DNS Resolver project","country_code":"AU"}]}}`)
	})
	mux.HandleFunc("/asn/13335/prefixes", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status":"ok","data":{"ipv4_prefixes":[{"prefix":"1.1.1.0/24","name":"APNIC-LABS","description":"APNIC Research","country_code":"AU"},{"prefix":"104.16.0.0/13","name":"CF","description":"Cloudflare","country_code":"US"}],"ipv6_prefixes":[{"prefix":"2606:4700::/32","name":"CF","description":"Cloudflare","country_code":"US"}]}}`)
	})
	mux.HandleFunc("/asn/13335", func(w http.ResponseWriter, r *http.Request) {
		// Be careful — this also matches /asn/13335/prefixes if order matters.
		// http.ServeMux longest-prefix wins, so /asn/13335/prefixes is already
		// claimed above. This handler is only hit for /asn/13335 exactly.
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status":"ok","data":{"asn":13335,"name":"CLOUDFLARENET","description_short":"Cloudflare, Inc.","description_full":["Cloudflare, Inc."],"country_code":"US"}}`)
	})
	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "ok",
			"data": map[string]any{
				"asns": []map[string]any{
					{"asn": 13335, "name": "CLOUDFLARENET", "description": "Cloudflare, Inc.", "country_code": "US"},
				},
			},
		})
	})
	return httptest.NewServer(mux)
}

func TestLookup_ByIP(t *testing.T) {
	srv := fakeBGPView(t)
	defer srv.Close()
	res := Lookup(context.Background(), Config{
		Inputs:      []string{"1.1.1.1"},
		BGPViewBase: srv.URL,
	})
	if len(res.IPMappings) != 1 || res.IPMappings[0].ASN != 13335 {
		t.Fatalf("expected 1 mapping for ASN 13335, got %v", res.IPMappings)
	}
	if res.Stats.ASNs != 1 {
		t.Errorf("expected 1 ASN, got %d", res.Stats.ASNs)
	}
	if res.Stats.IPv4Prefixes < 2 || res.Stats.IPv6Prefixes < 1 {
		t.Errorf("expected ≥2 v4 + ≥1 v6 prefixes, got v4=%d v6=%d", res.Stats.IPv4Prefixes, res.Stats.IPv6Prefixes)
	}
}

func TestLookup_ByASN(t *testing.T) {
	srv := fakeBGPView(t)
	defer srv.Close()
	for _, in := range []string{"AS13335", "13335"} {
		res := Lookup(context.Background(), Config{
			Inputs:      []string{in},
			BGPViewBase: srv.URL,
			SkipIPv6:    true,
		})
		if res.Stats.ASNs != 1 {
			t.Errorf("input %q: expected 1 ASN, got %d", in, res.Stats.ASNs)
		}
		// With v6 disabled, only v4 should be counted.
		if res.Stats.IPv6Prefixes != 0 {
			t.Errorf("input %q: expected 0 v6 prefixes with IncludeIPv6=false, got %d", in, res.Stats.IPv6Prefixes)
		}
	}
}

func TestLookup_ByOrg(t *testing.T) {
	srv := fakeBGPView(t)
	defer srv.Close()
	res := Lookup(context.Background(), Config{
		Inputs:      []string{"cloudflare"}, // org search
		BGPViewBase: srv.URL,
	})
	if res.Stats.ASNs == 0 {
		t.Errorf("expected ≥1 ASN from org search, got 0")
	}
}

func TestLookup_MaxPrefixesCap(t *testing.T) {
	srv := fakeBGPView(t)
	defer srv.Close()
	res := Lookup(context.Background(), Config{
		Inputs:            []string{"AS13335"},
		BGPViewBase:       srv.URL,
		MaxPrefixesPerASN: 1,
	})
	if len(res.Prefixes) != 1 {
		t.Errorf("expected 1 prefix under cap, got %d", len(res.Prefixes))
	}
}

func TestLooksLikeHost(t *testing.T) {
	cases := map[string]bool{
		"example.com": true,
		"1.2.3.4":     true, // also looks-like-host, but earlier classifier handles IP
		"AS13335":     false,
		"13335":       false,
		"foo bar":     false,
		"10.0.0.0/8":  false,
		"":            false,
	}
	for in, want := range cases {
		if got := looksLikeHost(in); got != want {
			t.Errorf("looksLikeHost(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestLookup_CombinesInputs(t *testing.T) {
	srv := fakeBGPView(t)
	defer srv.Close()
	res := Lookup(context.Background(), Config{
		Inputs:      []string{"AS13335", "1.1.1.1"}, // both expand same ASN
		BGPViewBase: srv.URL,
	})
	// Both inputs should converge on 1 ASN.
	if res.Stats.ASNs != 1 {
		t.Errorf("expected 1 ASN (combined), got %d", res.Stats.ASNs)
	}
	// One IPMapping
	if len(res.IPMappings) != 1 {
		t.Errorf("expected 1 IPMapping, got %d", len(res.IPMappings))
	}
	// Prefixes should be deduplicated (1.1.1.0/24 appears in both /ip and /prefixes).
	seen := map[string]int{}
	for _, p := range res.Prefixes {
		seen[p.CIDR]++
	}
	for k, v := range seen {
		if v > 1 {
			t.Errorf("prefix %q appears %d times — should be deduped", k, v)
		}
	}
	if !strings.HasPrefix(res.Prefixes[0].CIDR, "1.") && !strings.HasPrefix(res.Prefixes[0].CIDR, "104.") {
		t.Errorf("unexpected first prefix: %v", res.Prefixes[0])
	}
}
