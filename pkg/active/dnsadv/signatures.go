package dnsadv

// takeoverSig is one entry in our curated takeover fingerprint table.
//
// A subdomain is suspect when its CNAME chain ends in any of CNAMEMatch
// (case-insensitive suffix or substring), AND an HTTP GET to the FQDN returns
// a body containing ANY of HTTPMatch (case-sensitive — the SaaS provider's
// error pages are deterministic English strings).
//
// Vulnerable indicates whether the public takeover technique is currently
// known to be exploitable. Some entries are kept here even when not
// exploitable, because the dangling CNAME alone is a hygiene/leak signal.
type takeoverSig struct {
	Service    string   // canonical service name
	CNAMEMatch []string // case-insensitive substrings of the CNAME target
	HTTPMatch  []string // case-sensitive substrings of the HTTP body
	Vulnerable bool     // whether the takeover is exploitable as of writing
	Doc        string   // brief reference / URL
}

// takeoverSigs is the curated list. Sourced from EdOverflow/can-i-take-over-xyz
// and similar community references, with manual verification of CNAME suffixes
// and English error strings. Order matters — first match wins.
var takeoverSigs = []takeoverSig{
	// ----- High-value: still commonly exploitable -----
	{
		Service:    "GitHub Pages",
		CNAMEMatch: []string{"github.io", "github.map.fastly.net"},
		HTTPMatch:  []string{"There isn't a GitHub Pages site here"},
		Vulnerable: true,
		Doc:        "https://github.com/EdOverflow/can-i-take-over-xyz#github",
	},
	{
		Service:    "AWS/S3",
		CNAMEMatch: []string{"s3.amazonaws.com", "s3-website"},
		HTTPMatch:  []string{"NoSuchBucket", "The specified bucket does not exist"},
		Vulnerable: true,
		Doc:        "https://github.com/EdOverflow/can-i-take-over-xyz#aws-s3",
	},
	{
		Service:    "Heroku",
		CNAMEMatch: []string{"herokudns.com", "herokuapp.com", "herokussl.com"},
		HTTPMatch:  []string{"No such app", "herokucdn.com/error-pages/no-such-app.html"},
		Vulnerable: true,
		Doc:        "https://github.com/EdOverflow/can-i-take-over-xyz#heroku",
	},
	{
		Service:    "Bitbucket",
		CNAMEMatch: []string{"bitbucket.io"},
		HTTPMatch:  []string{"Repository not found"},
		Vulnerable: true,
		Doc:        "https://github.com/EdOverflow/can-i-take-over-xyz#bitbucket",
	},
	{
		Service:    "Shopify",
		CNAMEMatch: []string{"myshopify.com"},
		HTTPMatch:  []string{"Sorry, this shop is currently unavailable", "Only one step left!"},
		Vulnerable: true,
		Doc:        "https://github.com/EdOverflow/can-i-take-over-xyz#shopify",
	},
	{
		Service:    "Tumblr",
		CNAMEMatch: []string{"domains.tumblr.com"},
		HTTPMatch:  []string{"Whatever you were looking for doesn't currently exist at this address"},
		Vulnerable: true,
		Doc:        "https://github.com/EdOverflow/can-i-take-over-xyz#tumblr",
	},
	{
		Service:    "Fastly",
		CNAMEMatch: []string{"fastly.net"},
		HTTPMatch:  []string{"Fastly error: unknown domain"},
		Vulnerable: true,
		Doc:        "https://github.com/EdOverflow/can-i-take-over-xyz#fastly",
	},
	{
		Service:    "Ghost",
		CNAMEMatch: []string{"ghost.io"},
		HTTPMatch:  []string{"The thing you were looking for is no longer here", "domain error"},
		Vulnerable: true,
		Doc:        "https://github.com/EdOverflow/can-i-take-over-xyz#ghost",
	},
	{
		Service:    "Pantheon",
		CNAMEMatch: []string{"pantheonsite.io"},
		HTTPMatch:  []string{"The gods are wise", "404 error unknown site"},
		Vulnerable: true,
		Doc:        "https://github.com/EdOverflow/can-i-take-over-xyz#pantheon",
	},
	{
		Service:    "Tilda",
		CNAMEMatch: []string{"tilda.ws"},
		HTTPMatch:  []string{"Please renew your subscription"},
		Vulnerable: true,
		Doc:        "https://github.com/EdOverflow/can-i-take-over-xyz#tilda",
	},
	{
		Service:    "Unbounce",
		CNAMEMatch: []string{"unbouncepages.com"},
		HTTPMatch:  []string{"The requested URL was not found on this server"},
		Vulnerable: true,
		Doc:        "https://github.com/EdOverflow/can-i-take-over-xyz#unbounce",
	},
	{
		Service:    "HelpJuice",
		CNAMEMatch: []string{"helpjuice.com"},
		HTTPMatch:  []string{"We could not find what you're looking for"},
		Vulnerable: true,
		Doc:        "https://github.com/EdOverflow/can-i-take-over-xyz#helpjuice",
	},
	{
		Service:    "HelpScout",
		CNAMEMatch: []string{"helpscoutdocs.com"},
		HTTPMatch:  []string{"No settings were found for this company"},
		Vulnerable: true,
		Doc:        "https://github.com/EdOverflow/can-i-take-over-xyz#helpscout",
	},
	{
		Service:    "Cargo",
		CNAMEMatch: []string{"cargocollective.com"},
		HTTPMatch:  []string{"404 Not Found"},
		Vulnerable: true,
		Doc:        "https://github.com/EdOverflow/can-i-take-over-xyz#cargo-collective",
	},
	{
		Service:    "StatusPage",
		CNAMEMatch: []string{"statuspage.io"},
		HTTPMatch:  []string{"You are being <a href=\"https://www.statuspage.io"},
		Vulnerable: true,
		Doc:        "https://github.com/EdOverflow/can-i-take-over-xyz#statuspage",
	},
	{
		Service:    "Surge.sh",
		CNAMEMatch: []string{"surge.sh"},
		HTTPMatch:  []string{"project not found"},
		Vulnerable: true,
		Doc:        "https://github.com/EdOverflow/can-i-take-over-xyz#surgesh",
	},
	{
		Service:    "Intercom",
		CNAMEMatch: []string{"custom.intercom.help"},
		HTTPMatch:  []string{"Uh oh. That page doesn't exist."},
		Vulnerable: true,
		Doc:        "https://github.com/EdOverflow/can-i-take-over-xyz#intercom",
	},
	{
		Service:    "LaunchRock",
		CNAMEMatch: []string{"launchrock.com"},
		HTTPMatch:  []string{"It looks like you may have taken a wrong turn somewhere"},
		Vulnerable: true,
		Doc:        "https://github.com/EdOverflow/can-i-take-over-xyz#launchrock",
	},
	{
		Service:    "ReadTheDocs",
		CNAMEMatch: []string{"readthedocs.io"},
		HTTPMatch:  []string{"unknown to Read the Docs"},
		Vulnerable: true,
		Doc:        "https://github.com/EdOverflow/can-i-take-over-xyz#readme",
	},
	{
		Service:    "Strikingly",
		CNAMEMatch: []string{"s.strikinglydns.com"},
		HTTPMatch:  []string{"PAGE NOT FOUND", "But if you're looking to build your own website"},
		Vulnerable: true,
		Doc:        "https://github.com/EdOverflow/can-i-take-over-xyz#strikingly",
	},
	{
		Service:    "Uservoice",
		CNAMEMatch: []string{"uservoice.com"},
		HTTPMatch:  []string{"This UserVoice subdomain is currently available"},
		Vulnerable: true,
		Doc:        "https://github.com/EdOverflow/can-i-take-over-xyz#uservoice",
	},
	{
		Service:    "Wordpress",
		CNAMEMatch: []string{"wordpress.com"},
		HTTPMatch:  []string{"Do you want to register"},
		Vulnerable: true,
		Doc:        "https://github.com/EdOverflow/can-i-take-over-xyz#wordpress",
	},
	{
		Service:    "Acquia",
		CNAMEMatch: []string{"acquia-sites.com"},
		HTTPMatch:  []string{"The site you are looking for could not be found"},
		Vulnerable: true,
		Doc:        "https://github.com/EdOverflow/can-i-take-over-xyz#acquia",
	},
	{
		Service:    "Netlify",
		CNAMEMatch: []string{"netlify.app", "netlify.com"},
		HTTPMatch:  []string{"Not Found - Request ID:"},
		Vulnerable: true,
		Doc:        "https://github.com/EdOverflow/can-i-take-over-xyz#netlify",
	},
	{
		Service:    "Vercel",
		CNAMEMatch: []string{"vercel-dns.com", "cname.vercel-dns.com"},
		HTTPMatch:  []string{"The deployment could not be found on Vercel"},
		Vulnerable: true,
		Doc:        "https://github.com/EdOverflow/can-i-take-over-xyz#vercel",
	},
	{
		Service:    "Worksites.net",
		CNAMEMatch: []string{"alias.zerigo.com"},
		HTTPMatch:  []string{"Hello! Sorry, but the website you’re looking for doesn’t exist"},
		Vulnerable: true,
		Doc:        "https://github.com/EdOverflow/can-i-take-over-xyz#worksites",
	},

	// ----- Informational: signature matches but not directly exploitable -----
	{
		Service:    "Azure (cloudapp)",
		CNAMEMatch: []string{"cloudapp.net", "cloudapp.azure.com", "trafficmanager.net", "azurewebsites.net", "blob.core.windows.net"},
		HTTPMatch:  []string{"404 Web Site not found", "The specified blob does not exist"},
		Vulnerable: false,
		Doc:        "Microsoft now blocks the obvious takeover paths; dangling CNAME is still a leak",
	},
	{
		Service:    "Google Cloud Storage",
		CNAMEMatch: []string{"storage.googleapis.com"},
		HTTPMatch:  []string{"The specified bucket does not exist"},
		Vulnerable: false,
		Doc:        "GCS requires domain verification before claiming the bucket name; informational only",
	},
	{
		Service:    "Squarespace",
		CNAMEMatch: []string{"squarespace.com"},
		HTTPMatch:  []string{"No Such Account"},
		Vulnerable: false,
		Doc:        "Squarespace has hardened against takeover; signature kept for awareness",
	},
	{
		Service:    "Zendesk",
		CNAMEMatch: []string{"zendesk.com"},
		HTTPMatch:  []string{"Help Center Closed"},
		Vulnerable: false,
		Doc:        "Zendesk blocked re-registration of dangling subdomains in 2017",
	},
}
