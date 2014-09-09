import sys
import socket
import re
import MySQLdb


def suricata_rule(value, sid, name="", ref_url="", vtype="DOMAIN"):

	rules = []

	if ref_url.strip() != "":
		ref_url = re.sub('http(s)?://', '', ref_url.strip())
		reference = "reference:url,%s; "%ref_url
	else:
		reference = ""

	if vtype == "DOMAIN":
		try:
			ip_addr = socket.gethostbyname(value)
		except:
			ip_addr = None

		if ip_addr != None:
			print "[ ] "+value+" :: "+ip_addr
			rules.append('alert udp $HOME_NET any -> %s any (msg:"CONIX - %s - UDP traffic to %s (%s)"; sid:%d; rev:1; classtype:trojan-activity; metadata:impact_flag red; %s)'%(ip_addr, name, ip_addr, value, sid, reference))
			sid += 1
			rules.append('alert tcp $HOME_NET any -> %s any (msg:"CONIX - %s - TCP traffic to %s (%s)"; sid:%d; rev:1; classtype:trojan-activity; metadata:impact_flag red; %s)'%(ip_addr, name, ip_addr, value, sid, reference))
			sid += 1
		else:
			print >> sys.stderr, "[-] %s :: ip address cannot be resolved"%value

		members = value.split(".")
		dns_request = ""
		for m in members:
			dns_request += "|%0.2X|%s"%(len(m),m)
		rules.append('alert udp $HOME_NET any -> any 53 (msg:"CONIX - %s - DNS request for %s"; content:"|01 00 00 01 00 00 00 00 00 00|"; depth:20; offset: 2; content:"%s"; fast_pattern:only; nocase; sid:%d; rev:1; classtype:trojan-activity; metadata:impact_flag red; %s)'%(name, value, dns_request, sid, reference))
		sid += 1

	elif vtype == "URL":
		rules.append('alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"CONIX - %s - Related URL (%s)"; content:"%s"; http_uri; sid:%d; rev:1; classtype:trojan-activity; metadata:impact_flag red; %s)'%(name, value, value, sid, reference))
		sid += 1

	return rules, sid

def blacklist_sql(value, name, vtype="DOMAIN"):
	query = "INSERT INTO domains.blacklist(name, domain_match, match_type) VALUES (\"CONIX - %s\", \"%s\", \"%s\");"%(MySQLdb.escape_string(name), MySQLdb.escape_string(value), MySQLdb.escape_string(vtype))
	return query