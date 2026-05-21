package jscrawl

import (
	"net/url"
	"strings"

	"github.com/PuerkitoBio/goquery"
)

// extractForms walks an HTML body and turns every <form> element into a Form
// record (action resolved against pageURL, method uppercased, named inputs
// flattened). Returns nil when the body isn't parseable as HTML or contains
// no forms with names.
//
// We intentionally drop forms that have no named inputs AND a relative
// action equal to the page itself — they're usually decorative search bars
// embedded by template engines, not useful endpoints.
func extractForms(pageURL, body string) []*Form {
	base, err := url.Parse(pageURL)
	if err != nil {
		return nil
	}
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(body))
	if err != nil {
		return nil
	}
	var forms []*Form
	doc.Find("form").Each(func(_ int, s *goquery.Selection) {
		action, _ := s.Attr("action")
		method, _ := s.Attr("method")
		enctype, _ := s.Attr("enctype")
		method = strings.ToUpper(strings.TrimSpace(method))
		if method == "" {
			method = "GET"
		}
		absAction := pageURL
		actionRaw := strings.TrimSpace(action)
		if actionRaw != "" {
			if u, err := base.Parse(actionRaw); err == nil {
				u.Fragment = ""
				absAction = u.String()
			}
		}
		f := &Form{
			URL:     pageURL,
			Action:  absAction,
			Method:  method,
			EncType: strings.TrimSpace(strings.ToLower(enctype)),
		}
		s.Find("input, textarea, select").Each(func(_ int, in *goquery.Selection) {
			name, _ := in.Attr("name")
			name = strings.TrimSpace(name)
			if name == "" {
				return
			}
			typ, _ := in.Attr("type")
			val, _ := in.Attr("value")
			f.Inputs = append(f.Inputs, &FormInput{
				Name:  name,
				Type:  strings.ToLower(strings.TrimSpace(typ)),
				Value: val,
			})
		})
		// Skip forms that are clearly decoration: no inputs AND action ==
		// pageURL. Anything with at least one named input OR a non-trivial
		// action is worth recording.
		if len(f.Inputs) == 0 && f.Action == pageURL {
			return
		}
		forms = append(forms, f)
	})
	return forms
}

// collectParams pulls every query-string parameter name out of a URL.
// Returns nil for unparseable URLs (callers can ignore the empty slice).
func collectParams(rawURL string) []string {
	u, err := url.Parse(rawURL)
	if err != nil || u.RawQuery == "" {
		return nil
	}
	q := u.Query()
	if len(q) == 0 {
		return nil
	}
	out := make([]string, 0, len(q))
	for k := range q {
		k = strings.TrimSpace(k)
		if k != "" {
			out = append(out, k)
		}
	}
	return out
}
