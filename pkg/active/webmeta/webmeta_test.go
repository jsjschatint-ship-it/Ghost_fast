package webmeta

import (
	"strings"
	"testing"
)

func TestApplyHTMLMetaExtractsFields(t *testing.T) {
	r := &Report{FinalURL: "https://example.com/index.html"}
	applyHTMLMeta(r, `<html><head>
<title> Example  Site </title>
<meta name="description" content=" ACME portal ">
<meta property="og:title" content="ACME OG">
<link rel="canonical" href="/home">
<link rel="icon" href="/favicon.ico">
</head><body><a href="https://cdn.example.net/x.js">cdn</a><a href="/local">local</a></body></html>`)
	if r.Title != "Example Site" {
		t.Fatalf("title = %q", r.Title)
	}
	if r.Meta["description"] != "ACME portal" {
		t.Fatalf("description = %q", r.Meta["description"])
	}
	if r.OpenGraph["og:title"] != "ACME OG" {
		t.Fatalf("og:title = %q", r.OpenGraph["og:title"])
	}
	if r.Canonical != "https://example.com/home" {
		t.Fatalf("canonical = %q", r.Canonical)
	}
	if len(r.Icons) != 1 || r.Icons[0] != "https://example.com/favicon.ico" {
		t.Fatalf("icons = %#v", r.Icons)
	}
	if len(r.ExternalLinks) != 1 || r.ExternalLinks[0] != "https://cdn.example.net/x.js" {
		t.Fatalf("external links = %#v", r.ExternalLinks)
	}
}

func TestParseRobots(t *testing.T) {
	allows, disallows, sitemaps := parseRobots(`User-agent: *
Allow: /public
Disallow: /admin
Sitemap: /sitemap.xml
`, "https://example.com/robots.txt")
	if len(allows) != 1 || allows[0] != "https://example.com/public" {
		t.Fatalf("allows = %#v", allows)
	}
	if len(disallows) != 1 || disallows[0] != "https://example.com/admin" {
		t.Fatalf("disallows = %#v", disallows)
	}
	if len(sitemaps) != 1 || sitemaps[0] != "https://example.com/sitemap.xml" {
		t.Fatalf("sitemaps = %#v", sitemaps)
	}
}

func TestParseSitemap(t *testing.T) {
	urls, nested := parseSitemap(`<?xml version="1.0"?><urlset><url><loc>https://example.com/a</loc></url><url><loc>https://example.com/b</loc></url></urlset>`)
	if strings.Join(urls, ",") != "https://example.com/a,https://example.com/b" {
		t.Fatalf("urls = %#v", urls)
	}
	if len(nested) != 0 {
		t.Fatalf("nested = %#v", nested)
	}
	urls, nested = parseSitemap(`<?xml version="1.0"?><sitemapindex><sitemap><loc>https://example.com/s1.xml</loc></sitemap></sitemapindex>`)
	if len(urls) != 0 || len(nested) != 1 || nested[0] != "https://example.com/s1.xml" {
		t.Fatalf("urls=%#v nested=%#v", urls, nested)
	}
}

func TestCandidateURLs(t *testing.T) {
	got := candidateURLs("example.com", true)
	if len(got) != 2 || got[0] != "https://example.com" || got[1] != "http://example.com" {
		t.Fatalf("candidateURLs = %#v", got)
	}
	got = candidateURLs("http://example.com", true)
	if len(got) != 1 || got[0] != "http://example.com" {
		t.Fatalf("candidateURLs url = %#v", got)
	}
}
