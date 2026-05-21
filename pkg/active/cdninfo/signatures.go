package cdninfo

import "strings"

// vendorSig is one fingerprint rule.
type vendorSig struct {
	Vendor       string
	Kind         string   // cdn|waf|cloud_lb
	HeaderName   string   // empty if not a header rule
	HeaderValue  string   // substring (case-insensitive) — empty = any value
	CNAMEContain []string // substrings; ANY-match → hit
	BodyContain  []string // substrings (rare; e.g. WAF block pages)
}

// vendorSigs is the curated fingerprint database. Order isn't significant —
// every match is reported.
var vendorSigs = []vendorSig{
	// ---- Cloudflare ----
	{Vendor: "cloudflare", Kind: "cdn", HeaderName: "cf-ray"},
	{Vendor: "cloudflare", Kind: "cdn", HeaderName: "server", HeaderValue: "cloudflare"},
	{Vendor: "cloudflare", Kind: "cdn", HeaderName: "cf-cache-status"},
	{Vendor: "cloudflare", Kind: "cdn", CNAMEContain: []string{"cloudflare.net", "cloudflare.com"}},

	// ---- AWS CloudFront ----
	{Vendor: "aws_cloudfront", Kind: "cdn", HeaderName: "x-amz-cf-id"},
	{Vendor: "aws_cloudfront", Kind: "cdn", HeaderName: "x-amz-cf-pop"},
	{Vendor: "aws_cloudfront", Kind: "cdn", HeaderName: "via", HeaderValue: "cloudfront"},
	{Vendor: "aws_cloudfront", Kind: "cdn", CNAMEContain: []string{"cloudfront.net"}},
	// AWS ALB / ELB
	{Vendor: "aws_elb", Kind: "cloud_lb", HeaderName: "server", HeaderValue: "awselb"},
	{Vendor: "aws_elb", Kind: "cloud_lb", CNAMEContain: []string{"elb.amazonaws.com", "amazonaws.com"}},

	// ---- Akamai ----
	{Vendor: "akamai", Kind: "cdn", HeaderName: "x-akamai-transformed"},
	{Vendor: "akamai", Kind: "cdn", HeaderName: "x-akamai-request-id"},
	{Vendor: "akamai", Kind: "cdn", HeaderName: "akamai-ghost-ip"},
	{Vendor: "akamai", Kind: "cdn", HeaderName: "x-akamai-edgescape"},
	{Vendor: "akamai", Kind: "cdn", CNAMEContain: []string{"akamaiedge.net", "akamaihd.net", "akamai.net", "akamaitechnologies.com", "edgekey.net", "edgesuite.net"}},

	// ---- Fastly ----
	{Vendor: "fastly", Kind: "cdn", HeaderName: "x-fastly-request-id"},
	{Vendor: "fastly", Kind: "cdn", HeaderName: "x-served-by", HeaderValue: "cache-"},
	{Vendor: "fastly", Kind: "cdn", HeaderName: "server", HeaderValue: "fastly"},
	{Vendor: "fastly", Kind: "cdn", CNAMEContain: []string{"fastly.net", "fastlylb.net"}},

	// ---- Azure / Microsoft ----
	{Vendor: "azure_frontdoor", Kind: "cdn", HeaderName: "x-azure-ref"},
	{Vendor: "azure_frontdoor", Kind: "cdn", CNAMEContain: []string{"azurefd.net", "azureedge.net"}},
	{Vendor: "azure_app_service", Kind: "cloud_lb", CNAMEContain: []string{"azurewebsites.net"}},

	// ---- Google Cloud ----
	{Vendor: "gcp_load_balancer", Kind: "cloud_lb", HeaderName: "server", HeaderValue: "gws"},
	{Vendor: "gcp_load_balancer", Kind: "cloud_lb", CNAMEContain: []string{"ghs.googlehosted.com", "lb.googleusercontent.com"}},

	// ---- 国内 CDN ----
	{Vendor: "aliyun_cdn", Kind: "cdn", HeaderName: "via", HeaderValue: "alicdn"},
	{Vendor: "aliyun_cdn", Kind: "cdn", HeaderName: "eagleid"},
	{Vendor: "aliyun_cdn", Kind: "cdn", HeaderName: "ali-swift-global-savetime"},
	{Vendor: "aliyun_cdn", Kind: "cdn", CNAMEContain: []string{"alikunlun.com", "kunlunca.com", "kunlunar.com", "kunlunwe.com", "kunlunsl.com", "alicdn.com", "alikunlun.net"}},
	{Vendor: "aliyun_waf", Kind: "waf", HeaderName: "ali-swift-global-savetime"},
	{Vendor: "aliyun_oss", Kind: "cloud_lb", HeaderName: "server", HeaderValue: "aliyunoss"},
	{Vendor: "aliyun_oss", Kind: "cloud_lb", CNAMEContain: []string{"aliyuncs.com", "oss-"}},
	{Vendor: "aliyun_slb", Kind: "cloud_lb", CNAMEContain: []string{"aliyun-inc.com", "slb-"}},

	{Vendor: "tencent_cloud_cdn", Kind: "cdn", HeaderName: "server", HeaderValue: "tcdn"},
	{Vendor: "tencent_cloud_cdn", Kind: "cdn", HeaderName: "x-nws-log-uuid"},
	{Vendor: "tencent_cloud_cdn", Kind: "cdn", CNAMEContain: []string{"cdntip.com", "tcdn.qq.com", "qcloudcdn.cn", "dnspod.cn", "qcloudcdn.com"}},
	{Vendor: "tencent_cos", Kind: "cloud_lb", CNAMEContain: []string{"myqcloud.com", "cos.tencentyun.com"}},

	{Vendor: "baidu_cdn", Kind: "cdn", HeaderName: "server", HeaderValue: "jsp3"},
	{Vendor: "baidu_cdn", Kind: "cdn", CNAMEContain: []string{"bdydns.com", "jomodns.com", "baidu.com", "baiducdn.com"}},

	{Vendor: "huawei_cloud_cdn", Kind: "cdn", CNAMEContain: []string{"hwcdn.net", "cdnhwc1.com", "myhuaweicloud.com"}},

	{Vendor: "qiniu_cdn", Kind: "cdn", HeaderName: "x-qiniu-request-id"},
	{Vendor: "qiniu_cdn", Kind: "cdn", CNAMEContain: []string{"qbox.me", "qiniudns.com", "qiniucdn.com"}},

	{Vendor: "wangsu", Kind: "cdn", CNAMEContain: []string{"wsdvs.com", "wscdns.com", "wswebcdn.com", "lxdns.com", "ourwebpic.com", "wsglb0.com"}},

	{Vendor: "upyun", Kind: "cdn", HeaderName: "server", HeaderValue: "marco"},
	{Vendor: "upyun", Kind: "cdn", CNAMEContain: []string{"upaiyun.com", "upyuncdn.com"}},

	// ---- Other CDN/WAF ----
	{Vendor: "incapsula_imperva", Kind: "waf", HeaderName: "x-iinfo"},
	{Vendor: "incapsula_imperva", Kind: "waf", HeaderName: "x-cdn", HeaderValue: "incapsula"},
	{Vendor: "sucuri", Kind: "waf", HeaderName: "x-sucuri-id"},
	{Vendor: "sucuri", Kind: "waf", HeaderName: "server", HeaderValue: "sucuri/cloudproxy"},
	{Vendor: "f5_big_ip", Kind: "waf", HeaderName: "x-waf-event-info"},
	{Vendor: "f5_big_ip", Kind: "waf", HeaderName: "server", HeaderValue: "bigip"},
	{Vendor: "stackpath", Kind: "cdn", HeaderName: "x-cdn", HeaderValue: "stackpath"},
	{Vendor: "stackpath", Kind: "cdn", CNAMEContain: []string{"stackpathdns.com", "stackpathcdn.com"}},
	{Vendor: "cdn77", Kind: "cdn", CNAMEContain: []string{"cdn77.org", "cdn77.com"}},
	{Vendor: "bunnycdn", Kind: "cdn", CNAMEContain: []string{"b-cdn.net", "bunnycdn.com"}},
	{Vendor: "keycdn", Kind: "cdn", CNAMEContain: []string{"kxcdn.com"}},
	{Vendor: "edgio_limelight", Kind: "cdn", CNAMEContain: []string{"llnwd.net", "edgecast.net", "edgesuite.net"}},
	{Vendor: "section.io", Kind: "cdn", CNAMEContain: []string{"section.io", "squixa.net"}},
	{Vendor: "varnish", Kind: "cdn", HeaderName: "via", HeaderValue: "varnish"},
	{Vendor: "varnish", Kind: "cdn", HeaderName: "x-varnish"},

	// ---- 国产 / 其他 WAF ----
	{Vendor: "safe3_waf", Kind: "waf", HeaderName: "x-powered-by-360wzb"},
	{Vendor: "qiankun_waf", Kind: "waf", HeaderName: "qiankun-id"},
	{Vendor: "anquanbao_waf", Kind: "waf", HeaderName: "x-powered-by-anquanbao"},
	{Vendor: "yundun_360", Kind: "waf", HeaderName: "x-waf-status"},
	{Vendor: "yundun_360", Kind: "waf", HeaderName: "server", HeaderValue: "qianxin-waf"},
	{Vendor: "knownsec_jiasule", Kind: "waf", HeaderName: "x-waf-rule", HeaderValue: "jiasule"},
	{Vendor: "knownsec_jiasule", Kind: "waf", HeaderName: "server", HeaderValue: "jiasule-waf"},
	{Vendor: "knownsec_jiasule", Kind: "waf", CNAMEContain: []string{"jiashule.com", "jsl-cdn.com"}},
}

// classifyHeaders runs every header-style rule against the response headers.
func classifyHeaders(headers map[string]string) []*VendorHit {
	seen := map[string]struct{}{}
	var out []*VendorHit
	for _, sig := range vendorSigs {
		if sig.HeaderName == "" {
			continue
		}
		v, ok := getCanonical(headers, sig.HeaderName)
		if !ok {
			continue
		}
		if sig.HeaderValue != "" && !strings.Contains(strings.ToLower(v), strings.ToLower(sig.HeaderValue)) {
			continue
		}
		key := sig.Vendor + "|header|" + sig.HeaderName
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, &VendorHit{
			Vendor: sig.Vendor, Kind: sig.Kind, Source: "header",
			Evidence: sig.HeaderName + ": " + v,
		})
	}
	return out
}

// classifyCNAME runs every CNAME-style rule against the resolved CNAME chain.
func classifyCNAME(chain []string) []*VendorHit {
	seen := map[string]struct{}{}
	var out []*VendorHit
	low := make([]string, len(chain))
	for i, c := range chain {
		low[i] = strings.ToLower(c)
	}
	for _, sig := range vendorSigs {
		if len(sig.CNAMEContain) == 0 {
			continue
		}
		for _, needle := range sig.CNAMEContain {
			n := strings.ToLower(needle)
			matched := ""
			for _, c := range low {
				if strings.Contains(c, n) {
					matched = c
					break
				}
			}
			if matched == "" {
				continue
			}
			key := sig.Vendor + "|cname"
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, &VendorHit{
				Vendor: sig.Vendor, Kind: sig.Kind, Source: "cname",
				Evidence: matched + " (matches " + needle + ")",
			})
			break
		}
	}
	return out
}

// getCanonical case-insensitively looks up a header from a flat map.
func getCanonical(h map[string]string, name string) (string, bool) {
	for k, v := range h {
		if strings.EqualFold(k, name) {
			return v, true
		}
	}
	return "", false
}
