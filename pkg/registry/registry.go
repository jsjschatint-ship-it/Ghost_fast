// Package registry registers public-edition data sources and engines.
package registry

import (
	"github.com/wgpsec/ENScan/pkg/engine/fofa"
	"github.com/wgpsec/ENScan/pkg/engine/hunter"
	"github.com/wgpsec/ENScan/pkg/engine/quake"
	enginsh "github.com/wgpsec/ENScan/pkg/engine/shodan"
	"github.com/wgpsec/ENScan/pkg/engine/zerozone"
	enginzm "github.com/wgpsec/ENScan/pkg/engine/zoomeye"
	"github.com/wgpsec/ENScan/pkg/source"
	"github.com/wgpsec/ENScan/pkg/source/abusech"
	"github.com/wgpsec/ENScan/pkg/source/abuseipdb"
	"github.com/wgpsec/ENScan/pkg/source/app_market_search"
	"github.com/wgpsec/ENScan/pkg/source/asn_recon"
	"github.com/wgpsec/ENScan/pkg/source/bdziyi"
	"github.com/wgpsec/ENScan/pkg/source/beianx"
	"github.com/wgpsec/ENScan/pkg/source/bgp_he"
	"github.com/wgpsec/ENScan/pkg/source/bgpview"
	"github.com/wgpsec/ENScan/pkg/source/binaryedge"
	"github.com/wgpsec/ENScan/pkg/source/censys"
	"github.com/wgpsec/ENScan/pkg/source/certspotter"
	"github.com/wgpsec/ENScan/pkg/source/chaos"
	"github.com/wgpsec/ENScan/pkg/source/chinaz"
	"github.com/wgpsec/ENScan/pkg/source/ci_secret_search"
	"github.com/wgpsec/ENScan/pkg/source/cloud_bucket"
	"github.com/wgpsec/ENScan/pkg/source/company_structure_api"
	"github.com/wgpsec/ENScan/pkg/source/ct_log"
	"github.com/wgpsec/ENScan/pkg/source/cve_match"
	"github.com/wgpsec/ENScan/pkg/source/daydaymap"
	"github.com/wgpsec/ENScan/pkg/source/dnsdumpster"
	"github.com/wgpsec/ENScan/pkg/source/email_regex"
	"github.com/wgpsec/ENScan/pkg/source/employee_dork"
	"github.com/wgpsec/ENScan/pkg/source/engine_adapter"
	"github.com/wgpsec/ENScan/pkg/source/fullhunt"
	"github.com/wgpsec/ENScan/pkg/source/gitee_code"
	"github.com/wgpsec/ENScan/pkg/source/github_code"
	"github.com/wgpsec/ENScan/pkg/source/greynoise"
	"github.com/wgpsec/ENScan/pkg/source/hackertarget"
	"github.com/wgpsec/ENScan/pkg/source/hibp"
	"github.com/wgpsec/ENScan/pkg/source/intelx"
	"github.com/wgpsec/ENScan/pkg/source/internetdb"
	"github.com/wgpsec/ENScan/pkg/source/ipinfo"
	"github.com/wgpsec/ENScan/pkg/source/ipv6_pii_scan"
	"github.com/wgpsec/ENScan/pkg/source/js_endpoints"
	"github.com/wgpsec/ENScan/pkg/source/leakix"
	"github.com/wgpsec/ENScan/pkg/source/maltiverse"
	"github.com/wgpsec/ENScan/pkg/source/misc_apis"
	"github.com/wgpsec/ENScan/pkg/source/misc_apis2"
	"github.com/wgpsec/ENScan/pkg/source/netdisk_search"
	"github.com/wgpsec/ENScan/pkg/source/netlas"
	"github.com/wgpsec/ENScan/pkg/source/onyphe"
	"github.com/wgpsec/ENScan/pkg/source/otx"
	"github.com/wgpsec/ENScan/pkg/source/path_pivot"
	"github.com/wgpsec/ENScan/pkg/source/pii_scan"
	"github.com/wgpsec/ENScan/pkg/source/rapiddns"
	"github.com/wgpsec/ENScan/pkg/source/secret_scan"
	"github.com/wgpsec/ENScan/pkg/source/securitytrails"
	"github.com/wgpsec/ENScan/pkg/source/source_map_leak"
	"github.com/wgpsec/ENScan/pkg/source/supply/auto"
	supplygh "github.com/wgpsec/ENScan/pkg/source/supply/github_org"
	"github.com/wgpsec/ENScan/pkg/source/supply/pivots"
	"github.com/wgpsec/ENScan/pkg/source/supply/vendor"
	"github.com/wgpsec/ENScan/pkg/source/threatminer"
	"github.com/wgpsec/ENScan/pkg/source/urlscan"
	"github.com/wgpsec/ENScan/pkg/source/virustotal"
	"github.com/wgpsec/ENScan/pkg/source/wayback"
	"github.com/wgpsec/ENScan/pkg/source/wayback_params"
	"github.com/wgpsec/ENScan/pkg/source/whois_reverse"
	"github.com/wgpsec/ENScan/pkg/source/zerozone_extra"
)

// AllSources returns all sources enabled in the public edition.
func AllSources() map[string]source.Source {
	m := make(map[string]source.Source)

	m["fofa"] = engine_adapter.New("fofa", fofa.NewFOFA())
	m["hunter"] = engine_adapter.New("hunter", hunter.NewHunter())
	m["quake"] = engine_adapter.New("quake", quake.NewQuake())
	shodanAdapter := engine_adapter.New("shodan", enginsh.NewShodan())
	m["shodan_engine"] = shodanAdapter
	m["zerozone"] = engine_adapter.New("zerozone", zerozone.NewZeroZone())
	zoomeyeAdapter := engine_adapter.New("zoomeye", enginzm.NewZoomEye())
	m["zoomeye_engine"] = zoomeyeAdapter

	m["abusech"] = abusech.NewAbuseCH()
	m["abuseipdb"] = abuseipdb.NewAbuseIPDB()
	m["app_market_search"] = app_market_search.NewAppMarketSearch()
	m["asn_recon"] = asn_recon.NewASNRecon()
	m["bdziyi_fofa"] = bdziyi.NewBDZiyiFOFA()
	m["bdziyi_icp"] = bdziyi.NewBDZiyiICP()
	m["bdziyi_ze"] = bdziyi.NewBDZiyiZE()
	m["beianx"] = beianx.NewBeianx()
	m["bgp_he"] = bgp_he.NewBGPHE()
	m["bgpview"] = bgpview.NewBGPView()
	m["binaryedge"] = binaryedge.NewBinaryEdge()
	m["censys"] = censys.NewCensys()
	m["certspotter"] = certspotter.NewCertSpotter()
	m["chaos"] = chaos.NewChaos()
	m["chinaz"] = chinaz.NewChinaz()
	m["ci_secret_search"] = ci_secret_search.NewCISecretSearch()
	m["cloud_bucket"] = cloud_bucket.NewCloudBucket()
	m["company_structure_api"] = company_structure_api.NewCompanyStructureAPI()
	m["ct_log"] = ct_log.NewCTLog()
	m["cve_match"] = cve_match.NewCVEMatch()
	m["daydaymap"] = daydaymap.NewDayDayMap()
	m["dnsdumpster"] = dnsdumpster.NewDNSDumpster()
	m["email_regex"] = email_regex.NewEmailRegex()
	m["employee_dork"] = employee_dork.NewEmployeeDork()
	m["fullhunt"] = fullhunt.NewFullHunt()
	m["gitee_code"] = gitee_code.NewGiteeCode()
	m["github_code"] = github_code.NewGitHubCode()
	m["greynoise"] = greynoise.NewGreyNoise()
	m["hackertarget"] = hackertarget.NewHackerTarget()
	m["hibp"] = hibp.NewHIBP()
	m["intelx"] = intelx.NewIntelX()
	m["internetdb"] = internetdb.NewInternetDB()
	m["ipinfo"] = ipinfo.NewIPInfo()
	m["ipv6_pii_scan"] = ipv6_pii_scan.NewIPv6PIIScan()
	m["js_endpoints"] = js_endpoints.NewJSEndpoints()
	m["leakix"] = leakix.NewLeakIX()
	m["maltiverse"] = maltiverse.NewMaltiverse()
	m["netdisk_search"] = netdisk_search.NewNetdiskSearch()
	m["netlas"] = netlas.NewNetlas()
	m["onyphe"] = onyphe.NewOnyphe()
	m["otx"] = otx.NewOTX()
	m["pii_scan"] = pii_scan.NewPIIScan()
	m["rapiddns"] = rapiddns.NewRapidDNS()
	m["secret_scan"] = secret_scan.NewSecretScan()
	m["securitytrails"] = securitytrails.NewSecurityTrails()
	m["shodan"] = shodanAdapter
	m["source_map_leak"] = source_map_leak.NewSourceMapLeak()
	m["threatminer"] = threatminer.NewThreatMiner()
	m["urlscan"] = urlscan.NewURLScan()
	m["virustotal"] = virustotal.NewVirusTotal()
	m["wayback_params"] = wayback_params.NewWaybackParams()
	m["whois_reverse"] = whois_reverse.NewWhoisReverse()
	m["zoomeye"] = zoomeyeAdapter

	m["commoncrawl"] = misc_apis.NewCommonCrawl()
	m["dnslytics"] = misc_apis.NewDNSlytics()
	m["viewdns"] = misc_apis.NewViewDNS()
	m["robtex"] = misc_apis.NewRobtex()
	m["ripestat"] = misc_apis.NewRIPEstat()
	m["rdap"] = misc_apis.NewRDAP()
	m["publicwww"] = misc_apis.NewPublicWWW()
	m["pulsedive"] = misc_apis.NewPulsedive()
	m["pdns_circl"] = misc_apis.NewPDNSCircl()
	m["pdns_mnemonic"] = misc_apis.NewPDNSMnemonic()
	m["emailrep"] = misc_apis.NewEmailRep()
	m["hunter_io"] = misc_apis.NewHunterIO()
	m["hunter_verify"] = misc_apis.NewHunterVerify()
	m["hudsonrock"] = misc_apis.NewHudsonRock()
	m["hunt_io"] = misc_apis.NewHuntIO()
	m["greynoise_community"] = misc_apis.NewGreyNoiseCommunity()
	m["github_commits"] = misc_apis.NewGitHubCommits()
	m["driftnet"] = misc_apis.NewDriftnet()

	m["path_pivot"] = path_pivot.New()
	m["wayback"] = wayback.New()
	m["zerozone_extra"] = zerozone_extra.New()
	m["supply_pivots"] = pivots.New()
	m["supply_auto"] = auto.New()
	m["supply_vendor"] = vendor.New()
	m["supply_github_org"] = supplygh.New()

	m["pgpkeys"] = misc_apis2.NewPGPKeys()
	m["psbdmp"] = misc_apis2.NewPsbdmp()
	m["proxynova_combo"] = misc_apis2.NewProxyNovaCombo()
	m["skymem"] = misc_apis2.NewSkyMem()
	m["validin"] = misc_apis2.NewValidin()
	m["searchengine"] = misc_apis2.NewSearchEngine()
	m["shodan_enrich"] = misc_apis2.NewShodanEnrich()
	m["opencorporates"] = misc_apis2.NewOpenCorporates()

	return m
}
