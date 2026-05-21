package whoisrdap

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// rdapDomain is a partial RDAP response object — only fields we surface.
type rdapDomain struct {
	ObjectClassName string   `json:"objectClassName"`
	Handle          string   `json:"handle"`
	LDHName         string   `json:"ldhName"`
	UnicodeName     string   `json:"unicodeName"`
	Status          []string `json:"status"`
	Events          []struct {
		Action string `json:"eventAction"`
		Date   string `json:"eventDate"`
	} `json:"events"`
	Nameservers []struct {
		LDHName string `json:"ldhName"`
	} `json:"nameservers"`
	Entities []rdapEntity `json:"entities"`
}

type rdapEntity struct {
	Handle     string   `json:"handle"`
	Roles      []string `json:"roles"`
	VCardArray []any    `json:"vcardArray"`
	PublicIDs  []struct {
		Type       string `json:"type"`
		Identifier string `json:"identifier"`
	} `json:"publicIds"`
	Entities []rdapEntity `json:"entities"`
}

// rdapIPNetwork covers the /ip RDAP shape.
type rdapIPNetwork struct {
	ObjectClassName string       `json:"objectClassName"`
	Handle          string       `json:"handle"`
	StartAddress    string       `json:"startAddress"`
	EndAddress      string       `json:"endAddress"`
	Name            string       `json:"name"`
	Type            string       `json:"type"`
	Country         string       `json:"country"`
	Status          []string     `json:"status"`
	Entities        []rdapEntity `json:"entities"`
	CIDR0           []struct {
		V4Prefix string `json:"v4prefix"`
		V6Prefix string `json:"v6prefix"`
		Length   int    `json:"length"`
	} `json:"cidr0_cidrs"`
}

// rdapForDomain queries https://rdap.org/domain/<name>. rdap.org acts as a
// universal redirector to the right TLD's RDAP server.
func rdapForDomain(ctx context.Context, client *http.Client, ua, domain string) (*rdapDomain, []byte, error) {
	url := "https://rdap.org/domain/" + domain
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Accept", "application/rdap+json,application/json")
	req.Header.Set("User-Agent", ua)
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, nil, fmt.Errorf("rdap: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	if err != nil {
		return nil, nil, err
	}
	var d rdapDomain
	if err := json.Unmarshal(body, &d); err != nil {
		return nil, body, fmt.Errorf("rdap json: %w", err)
	}
	return &d, body, nil
}

// rdapForIP queries https://rdap.org/ip/<ip>.
func rdapForIP(ctx context.Context, client *http.Client, ua, ip string) (*rdapIPNetwork, []byte, error) {
	url := "https://rdap.org/ip/" + ip
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Accept", "application/rdap+json,application/json")
	req.Header.Set("User-Agent", ua)
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, nil, fmt.Errorf("rdap: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	if err != nil {
		return nil, nil, err
	}
	var n rdapIPNetwork
	if err := json.Unmarshal(body, &n); err != nil {
		return nil, body, fmt.Errorf("rdap json: %w", err)
	}
	return &n, body, nil
}

// extractContacts walks the RDAP entities tree and converts each leaf into
// a flat Contact. The vCard array structure is: ["vcard", [["fn", {}, "text",
// "Alice Smith"], ["email", {}, "text", "alice@x"], …]].
func extractContacts(entities []rdapEntity) []*Contact {
	var out []*Contact
	for _, e := range entities {
		out = append(out, contactFromEntity(e))
		out = append(out, extractContacts(e.Entities)...) // recurse
	}
	// Drop entries that have no useful field set.
	filtered := out[:0]
	for _, c := range out {
		if c == nil {
			continue
		}
		if c.Name == "" && c.Organization == "" && c.Email == "" && c.Phone == "" {
			continue
		}
		filtered = append(filtered, c)
	}
	return filtered
}

func contactFromEntity(e rdapEntity) *Contact {
	c := &Contact{Role: strings.Join(e.Roles, ",")}
	if len(e.VCardArray) < 2 {
		return c
	}
	// vCardArray[1] is a slice of properties; each property is itself a slice.
	props, ok := e.VCardArray[1].([]any)
	if !ok {
		return c
	}
	for _, p := range props {
		row, ok := p.([]any)
		if !ok || len(row) < 4 {
			continue
		}
		key, _ := row[0].(string)
		val, _ := row[3].(string)
		switch strings.ToLower(key) {
		case "fn":
			c.Name = val
		case "org":
			// org is sometimes nested: row[3] is ["Org Name"] not a plain string.
			if arr, ok := row[3].([]any); ok && len(arr) > 0 {
				if s, ok := arr[0].(string); ok {
					c.Organization = s
				}
			} else {
				c.Organization = val
			}
		case "email":
			c.Email = strings.ToLower(val)
		case "tel":
			c.Phone = val
		case "adr":
			// Address is an array of 7 components: PO box, ext, street, locality,
			// region, postal code, country.
			if arr, ok := row[3].([]any); ok && len(arr) >= 7 {
				if s, ok := arr[6].(string); ok {
					c.Country = s
				}
			}
		}
	}
	return c
}

// applyRDAPDomain folds the RDAP response into a Record.
func applyRDAPDomain(rec *Record, d *rdapDomain) {
	rec.Handle = d.Handle
	rec.Domain = strings.ToLower(d.LDHName)
	if d.UnicodeName != "" {
		rec.Domain = strings.ToLower(d.UnicodeName)
	}
	rec.Status = d.Status
	for _, ns := range d.Nameservers {
		rec.Nameservers = append(rec.Nameservers, strings.ToLower(ns.LDHName))
	}
	for _, ev := range d.Events {
		switch strings.ToLower(ev.Action) {
		case "registration":
			rec.CreatedAt = ev.Date
		case "last changed", "last update of rdap database":
			if rec.UpdatedAt == "" {
				rec.UpdatedAt = ev.Date
			}
		case "expiration":
			rec.ExpiresAt = ev.Date
		}
	}
	// Pick registrar from any entity with "registrar" role.
	for _, e := range d.Entities {
		for _, r := range e.Roles {
			if strings.EqualFold(r, "registrar") {
				c := contactFromEntity(e)
				if c.Organization != "" {
					rec.Registrar = c.Organization
				} else if c.Name != "" {
					rec.Registrar = c.Name
				}
				for _, p := range e.PublicIDs {
					if strings.Contains(strings.ToLower(p.Type), "iana") {
						rec.RegistrarURL = "https://www.iana.org/assignments/registrar-ids/registrar-ids.xhtml#" + p.Identifier
					}
				}
			}
		}
	}
	rec.Contacts = append(rec.Contacts, extractContacts(d.Entities)...)
}

// applyRDAPIP folds an IP RDAP response into a Record.
func applyRDAPIP(rec *Record, n *rdapIPNetwork) {
	rec.Handle = n.Handle
	rec.IPOrg = n.Name
	rec.IPCountry = n.Country
	if len(n.CIDR0) > 0 {
		c := n.CIDR0[0]
		if c.V4Prefix != "" {
			rec.IPNetwork = fmt.Sprintf("%s/%d", c.V4Prefix, c.Length)
		} else if c.V6Prefix != "" {
			rec.IPNetwork = fmt.Sprintf("%s/%d", c.V6Prefix, c.Length)
		}
	}
	if rec.IPNetwork == "" && n.StartAddress != "" && n.EndAddress != "" {
		rec.IPNetwork = n.StartAddress + " - " + n.EndAddress
	}
	rec.Status = n.Status
	rec.Contacts = append(rec.Contacts, extractContacts(n.Entities)...)
}
