package runner

import "testing"

func TestClassify(t *testing.T) {
	cases := []struct {
		target string
		isDom  bool
		isIP   bool
		isURL  bool
		isMail bool
		isASN  bool
		isICP  bool
		isCo   bool
	}{
		{"example.com", true, false, false, false, false, false, false},
		{"8.8.8.8", false, true, false, false, false, false, false},
		{"https://x.com/a", false, false, true, false, false, false, false},
		{"test@example.com", false, false, false, true, false, false, false},
		{"AS15169", false, false, false, false, true, false, false},
		{"15169", false, false, false, false, true, false, false},
		{"京ICP证030247号", false, false, false, false, false, true, true},
		{"中国工商银行", false, false, false, false, false, false, true},
		{"Acme Inc", false, false, false, false, false, false, true},
	}
	for _, c := range cases {
		if got := isDomain(c.target); got != c.isDom {
			t.Errorf("isDomain(%q)=%v want %v", c.target, got, c.isDom)
		}
		if got := isIP(c.target); got != c.isIP {
			t.Errorf("isIP(%q)=%v want %v", c.target, got, c.isIP)
		}
		if got := isURL(c.target); got != c.isURL {
			t.Errorf("isURL(%q)=%v want %v", c.target, got, c.isURL)
		}
		if got := isEmail(c.target); got != c.isMail {
			t.Errorf("isEmail(%q)=%v want %v", c.target, got, c.isMail)
		}
		if got := isASN(c.target); got != c.isASN {
			t.Errorf("isASN(%q)=%v want %v", c.target, got, c.isASN)
		}
		if got := isICP(c.target); got != c.isICP {
			t.Errorf("isICP(%q)=%v want %v", c.target, got, c.isICP)
		}
		if got := isCompany(c.target); got != c.isCo {
			t.Errorf("isCompany(%q)=%v want %v", c.target, got, c.isCo)
		}
	}
}
