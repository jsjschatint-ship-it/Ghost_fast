package whoisrdap

import (
	"strings"
	"testing"
)

// TestPickWhoisServer covers the per-TLD lookup table + multi-level TLDs.
func TestPickWhoisServer(t *testing.T) {
	cases := map[string]string{
		"example.com":        "whois.verisign-grs.com",
		"example.cn":         "whois.cnnic.cn",
		"example.com.cn":     "whois.cnnic.cn",
		"example.co.uk":      "whois.nic.uk",
		"example.io":         "whois.nic.io",
		"example.unknowntld": "whois.iana.org",
		"8.8.8.8":            "whois.arin.net",
	}
	for in, want := range cases {
		if got := pickWhoisServer(in); got != want {
			t.Errorf("pickWhoisServer(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestExtractReferral pulls the registrar's whois server from a referral body.
func TestExtractReferral(t *testing.T) {
	body := `
Domain Name: EXAMPLE.COM
Registry Domain ID: 2336799_DOMAIN_COM-VRSN
Registrar WHOIS Server: whois.markmonitor.com
Registrar URL: http://www.markmonitor.com
`
	got := extractReferral(body)
	if got != "whois.markmonitor.com" {
		t.Errorf("extractReferral returned %q", got)
	}
	// No referral → empty.
	if extractReferral("no referral here") != "" {
		t.Error("expected empty referral on miss")
	}
}

// TestParseWhoisFields covers the per-line field extractor.
func TestParseWhoisFields(t *testing.T) {
	body := `
Domain Name: EXAMPLE.COM
Registrar: MarkMonitor Inc.
Registrar URL: http://www.markmonitor.com
Creation Date: 1995-08-14T04:00:00Z
Updated Date: 2023-08-14T07:01:34Z
Registry Expiry Date: 2024-08-13T04:00:00Z
Domain Status: clientTransferProhibited
Domain Status: clientUpdateProhibited
Name Server: A.IANA-SERVERS.NET
Name Server: B.IANA-SERVERS.NET
Registrant Email: hostmaster@example.com
Registrant Name: ICANN
Registrant Organization: Internet Corporation for Assigned Names and Numbers
`
	p := parseWhoisFields(body)
	if p.Registrar != "MarkMonitor Inc." {
		t.Errorf("registrar = %q", p.Registrar)
	}
	if p.Created == "" || p.Expires == "" {
		t.Errorf("dates not parsed: %+v", p)
	}
	if len(p.Nameservers) != 2 {
		t.Errorf("expected 2 NS, got %v", p.Nameservers)
	}
	if len(p.Status) != 2 {
		t.Errorf("expected 2 status, got %v", p.Status)
	}
	if p.RegistrantEmail != "hostmaster@example.com" {
		t.Errorf("registrant email = %q", p.RegistrantEmail)
	}
	if !strings.HasPrefix(p.RegistrantOrg, "Internet") {
		t.Errorf("registrant org = %q", p.RegistrantOrg)
	}
}

// TestContactFromEntity covers the vCard parser shape.
func TestContactFromEntity(t *testing.T) {
	// Real RDAP vCard structure as a Go literal.
	entity := rdapEntity{
		Roles: []string{"registrant"},
		VCardArray: []any{
			"vcard",
			[]any{
				[]any{"version", map[string]any{}, "text", "4.0"},
				[]any{"fn", map[string]any{}, "text", "Alice Smith"},
				[]any{"org", map[string]any{}, "text", []any{"Acme Corp"}},
				[]any{"email", map[string]any{}, "text", "alice@acme.test"},
				[]any{"tel", map[string]any{}, "uri", "tel:+1-555-1234"},
				[]any{"adr", map[string]any{}, "text", []any{"", "", "1 Main St", "Springfield", "OR", "97477", "US"}},
			},
		},
	}
	c := contactFromEntity(entity)
	if c.Name != "Alice Smith" {
		t.Errorf("name = %q", c.Name)
	}
	if c.Organization != "Acme Corp" {
		t.Errorf("org = %q", c.Organization)
	}
	if c.Email != "alice@acme.test" {
		t.Errorf("email = %q", c.Email)
	}
	if c.Phone != "tel:+1-555-1234" {
		t.Errorf("phone = %q", c.Phone)
	}
	if c.Country != "US" {
		t.Errorf("country = %q", c.Country)
	}
	if !strings.Contains(c.Role, "registrant") {
		t.Errorf("role = %q", c.Role)
	}
}

// TestExtractContacts confirms the recursive walker filters empties.
func TestExtractContacts(t *testing.T) {
	entities := []rdapEntity{
		{Roles: []string{"registrant"}, VCardArray: []any{"vcard", []any{
			[]any{"fn", map[string]any{}, "text", "Bob"},
			[]any{"email", map[string]any{}, "text", "bob@x"},
		}}},
		{Roles: []string{"admin"}}, // no vCard — should be filtered
	}
	got := extractContacts(entities)
	if len(got) != 1 {
		t.Errorf("expected 1 non-empty contact, got %d", len(got))
	}
}

// TestApplyRDAPDomain folds a partial RDAP response into a Record.
func TestFoldRDAPDomain(t *testing.T) {
	d := &rdapDomain{
		Handle:  "EXAMPLE_DOMAIN",
		LDHName: "example.com",
		Status:  []string{"active"},
		Events: []struct {
			Action string `json:"eventAction"`
			Date   string `json:"eventDate"`
		}{
			{"registration", "1995-08-14T04:00:00Z"},
			{"expiration", "2030-08-13T04:00:00Z"},
		},
		Nameservers: []struct {
			LDHName string `json:"ldhName"`
		}{{"a.iana-servers.net"}, {"b.iana-servers.net"}},
		Entities: []rdapEntity{
			{Roles: []string{"registrar"}, VCardArray: []any{"vcard", []any{
				[]any{"fn", map[string]any{}, "text", "MarkMonitor Inc."},
				[]any{"org", map[string]any{}, "text", "MarkMonitor Inc."},
			}}},
		},
	}
	rec := &Record{Raw: map[string]string{}}
	applyRDAPDomain(rec, d)
	if rec.Domain != "example.com" {
		t.Errorf("domain = %q", rec.Domain)
	}
	if rec.Registrar != "MarkMonitor Inc." {
		t.Errorf("registrar = %q", rec.Registrar)
	}
	if rec.CreatedAt == "" || rec.ExpiresAt == "" {
		t.Errorf("dates missing: %+v", rec)
	}
	if len(rec.Nameservers) != 2 {
		t.Errorf("nameservers = %v", rec.Nameservers)
	}
}

func TestParseViewDNSDomains(t *testing.T) {
	html := `<table><tr><td>example.com</td></tr><tr><td>Sibling.NET</td></tr><tr><td>example.com</td></tr></table>`
	got := parseViewDNSDomains(html, 10)
	if len(got) != 2 {
		t.Fatalf("expected 2 domains, got %v", got)
	}
	if got[1] != "sibling.net" {
		t.Fatalf("expected lower-case domain, got %q", got[1])
	}
}

func TestParseWhoisXMLDomains(t *testing.T) {
	got := parseWhoisXMLDomains([]byte(`{"domainsList":["a.com","b.net","c.org"]}`), 2)
	if len(got) != 2 || got[0] != "a.com" || got[1] != "b.net" {
		t.Fatalf("unexpected domains: %v", got)
	}
}

func TestReverseWhoisPivots(t *testing.T) {
	rec := &Record{Contacts: []*Contact{
		{Role: "registrant", Name: "Example Inc", Organization: "Example Org", Email: "Admin@Example.com"},
		{Role: "tech", Organization: "Example Org", Email: "Admin@Example.com"},
	}}
	got := reverseWhoisPivots(rec)
	if len(got) != 3 {
		t.Fatalf("expected 3 unique pivots, got %v", got)
	}
	if got[0] != "admin@example.com" {
		t.Fatalf("expected normalized email first, got %q", got[0])
	}
}
