package dnsrecord

import (
	"strings"
	"testing"
)

// TestClassifyTXT_KnownProviders feeds a representative TXT body and
// confirms every recognised token is surfaced.
func TestClassifyTXT_KnownProviders(t *testing.T) {
	cases := map[string]string{
		"google-site-verification=abcDEFghi123":                     "google_workspace",
		"github-verification-12345=hash":                            "github",
		"atlassian-domain-verification=ABCDEFG":                     "atlassian",
		"ms=ms12345678":                                             "microsoft_365",
		"facebook-domain-verification=xyz":                          "facebook",
		"v=spf1 include:_spf.google.com include:amazonses.com ~all": "google_workspace",
		"v=spf1 include:spf.mail.qq.com -all":                       "tencent_exmail",
		"dingtalk-site-verification=DINGTALK123":                    "dingtalk",
		"aliyun-site-verification=ABC":                              "aliyun",
		"amazonses:abcd1234":                                        "aws_ses",
		"apple-domain-verification=APPLE":                           "apple",
	}
	for body, wantProvider := range cases {
		matches := classifyTXT(body)
		if len(matches) == 0 {
			t.Errorf("no match for %q", body)
			continue
		}
		found := false
		for _, m := range matches {
			if m.Provider == wantProvider {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected provider %q for %q, got %v", wantProvider, body, matches)
		}
	}
}

// TestClassifyTXT_ExtractsValue confirms that rules with a regex capture
// pull the token value out, not just the rule match.
func TestClassifyTXT_ExtractsValue(t *testing.T) {
	m := classifyTXT("google-site-verification=abc123def")
	if len(m) == 0 || m[0].Value != "abc123def" {
		t.Errorf("expected value=abc123def, got %v", m)
	}
}

// TestClassifyTXT_MultipleIncludes: one SPF TXT can declare multiple SaaS
// providers — we expect each to fire.
func TestClassifyTXT_MultipleIncludes(t *testing.T) {
	txt := "v=spf1 include:_spf.google.com include:amazonses.com include:sendgrid.net include:mailgun.org -all"
	got := classifyTXT(txt)
	want := []string{"google_workspace", "aws_ses", "sendgrid", "mailgun"}
	have := map[string]bool{}
	for _, m := range got {
		have[m.Provider] = true
	}
	for _, w := range want {
		if !have[w] {
			t.Errorf("expected provider %q, got %v", w, have)
		}
	}
}

// TestDeriveEmail covers SPF/DMARC parsing + MX listing.
func TestDeriveEmail(t *testing.T) {
	rrs := []*RR{
		{Type: "MX", Name: "x.com", Value: "aspmx.l.google.com", Priority: 10},
		{Type: "MX", Name: "x.com", Value: "alt1.aspmx.l.google.com", Priority: 20},
		{Type: "TXT", Name: "x.com", Value: "v=spf1 include:_spf.google.com include:amazonses.com ~all"},
		{Type: "DMARC", Name: "_dmarc.x.com", Value: "v=DMARC1; p=reject; rua=mailto:dmarc@x.com"},
	}
	e := deriveEmail(rrs)
	if len(e.MXProviders) != 2 {
		t.Errorf("expected 2 MX, got %v", e.MXProviders)
	}
	if !strings.HasPrefix(e.SPF, "v=spf1") {
		t.Errorf("SPF not captured: %q", e.SPF)
	}
	if len(e.SPFIncludes) != 2 {
		t.Errorf("expected 2 SPF includes, got %v", e.SPFIncludes)
	}
	if e.DMARCPolicy != "reject" {
		t.Errorf("DMARC policy not parsed, got %q", e.DMARCPolicy)
	}
}

// TestNormalizeServersAddsPort verifies fall-back behaviour.
func TestNormalizeServersAddsPort(t *testing.T) {
	out := normalizeServers([]string{"1.1.1.1", "9.9.9.9:5353", ""})
	if len(out) != 2 {
		t.Fatalf("expected 2 servers, got %v", out)
	}
	if out[0] != "1.1.1.1:53" || out[1] != "9.9.9.9:5353" {
		t.Errorf("got %v", out)
	}
	def := normalizeServers(nil)
	if len(def) == 0 {
		t.Error("expected default servers when input empty")
	}
}
