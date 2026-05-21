package portscan

// wellKnownServices maps the most common TCP port numbers to a short service
// name. Not exhaustive — only covers ports likely to appear in a top-1000
// scan against modern infrastructure. Used purely for human-friendly result
// labelling; do not use for protocol selection.
var wellKnownServices = map[int]string{
	7: "echo", 9: "discard", 13: "daytime", 17: "qotd", 19: "chargen",
	20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
	37: "time", 43: "whois", 53: "dns", 67: "dhcp", 69: "tftp",
	79: "finger", 80: "http", 88: "kerberos", 109: "pop2", 110: "pop3",
	111: "rpcbind", 113: "ident", 119: "nntp", 123: "ntp", 135: "msrpc",
	137: "netbios-ns", 138: "netbios-dgm", 139: "netbios-ssn", 143: "imap",
	161: "snmp", 162: "snmptrap", 179: "bgp", 199: "smux", 201: "appletalk",
	389: "ldap", 427: "svrloc", 443: "https", 444: "snpp", 445: "smb",
	464: "kpasswd", 465: "smtps", 500: "isakmp", 513: "rlogin", 514: "syslog",
	515: "lpd", 543: "klogin", 544: "kshell", 548: "afp", 554: "rtsp",
	563: "nntps", 587: "submission", 593: "msrpc", 631: "ipp", 636: "ldaps",
	646: "ldp", 873: "rsync", 902: "vmware-auth", 989: "ftps-data", 990: "ftps",
	993: "imaps", 995: "pop3s", 1025: "msrpc", 1080: "socks", 1099: "java-rmi",
	1158: "oracle-em", 1194: "openvpn", 1311: "rxmon", 1433: "mssql", 1434: "mssql-mon",
	1521: "oracle", 1604: "icabrowser", 1701: "l2tp", 1723: "pptp", 1755: "wms",
	1900: "upnp", 2000: "cisco-sccp", 2049: "nfs", 2082: "cpanel",
	2083: "cpanel-ssl", 2086: "whm", 2087: "whm-ssl", 2095: "webmail",
	2096: "webmail-ssl", 2121: "ftp-alt", 2181: "zookeeper", 2222: "ssh-alt",
	2375: "docker", 2376: "docker-tls", 2483: "oracle-tns", 2484: "oracle-tns-ssl",
	2638: "sybase", 3000: "grafana", 3001: "node-alt", 3128: "squid",
	3268: "ldap-gc", 3269: "ldaps-gc", 3306: "mysql", 3389: "rdp",
	3690: "svn", 4000: "icq", 4040: "yo-master", 4369: "epmd", 4444: "krb524",
	4500: "ipsec-nat-t", 4567: "tram", 4848: "glassfish", 5000: "upnp",
	5001: "commplex-link", 5060: "sip", 5061: "sips", 5222: "xmpp-client",
	5269: "xmpp-server", 5353: "mdns", 5432: "postgres", 5555: "freeciv",
	5601: "kibana", 5672: "amqp", 5683: "coap", 5800: "vnc-http",
	5900: "vnc", 5938: "teamviewer", 5984: "couchdb", 5985: "winrm",
	5986: "winrm-https", 6000: "x11", 6379: "redis", 6443: "kubernetes-api",
	6481: "servicetags", 6660: "irc", 6661: "irc", 6662: "irc", 6663: "irc",
	6664: "irc", 6665: "irc", 6666: "irc", 6667: "irc", 6697: "ircs",
	7000: "afs3", 7001: "weblogic", 7002: "weblogic-ssl", 7077: "spark",
	7474: "neo4j", 7547: "tr-069", 7777: "cba8", 8000: "http-alt",
	8001: "http-alt", 8008: "http-alt", 8009: "ajp", 8010: "xmpp-conference",
	8020: "hadoop-namenode", 8042: "hadoop-rm", 8060: "fido", 8069: "odoo",
	8080: "http-proxy", 8081: "http-alt", 8086: "influxdb", 8087: "graylog",
	8088: "hadoop-rm-ui", 8089: "splunk", 8090: "atlassian-confluence",
	8091: "couchbase-mgmt", 8161: "activemq", 8200: "vault", 8222: "vmware-fdm",
	8333: "bitcoin", 8388: "shadowsocks", 8443: "https-alt", 8500: "consul",
	8530: "wsus", 8531: "wsus-ssl", 8649: "ganglia", 8686: "jmx",
	8761: "eureka", 8834: "nessus", 8888: "http-alt", 9000: "sonar",
	9001: "tor", 9042: "cassandra", 9060: "websphere", 9090: "prometheus",
	9091: "transmission-rpc", 9092: "kafka", 9100: "printer", 9200: "elasticsearch",
	9300: "elastic-tcp", 9418: "git", 9595: "pichat", 9999: "abyss",
	10000: "webmin", 10250: "kubelet", 11211: "memcached", 12345: "netbus",
	13720: "netbackup", 13722: "netbackup", 15672: "rabbitmq-mgmt",
	16080: "osx-server-admin", 16992: "amt", 16993: "amt-ssl",
	17000: "isode-dua", 17988: "intel-rci-mp", 18080: "monero",
	19150: "gkrellm", 20000: "dnp", 21025: "stardew-valley",
	23023: "ssh-alt", 24800: "synergy", 25565: "minecraft",
	27017: "mongodb", 27018: "mongodb-shard", 27019: "mongodb-config",
	28017: "mongodb-http", 30000: "ndmps", 32400: "plex", 32764: "filenet-rpc",
	37777: "dahua-dvr", 41794: "crestron-cip", 47808: "bacnet",
	49152: "msrpc", 50000: "ibm-db2", 50030: "hadoop-jobtracker",
	50060: "hadoop-tasktracker", 50070: "hadoop-namenode-ui",
	50075: "hadoop-datanode", 50090: "hadoop-snn", 54321: "snmptrap-alt",
	60000: "linkrest", 61613: "stomp", 64738: "mumble",
}

// wellKnownService returns the canonical short service name for the given port,
// or "" when the port is not in the curated table.
func wellKnownService(port int) string {
	if name, ok := wellKnownServices[port]; ok {
		return name
	}
	return ""
}
