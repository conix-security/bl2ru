import sys
import socket
import re
import MySQLdb


def suricata_rule(value, sid, name="", ref_url="", vtype="DOMAIN", rule_tag=""):

	rules = []

	if ref_url.strip() != "":
		ref_url = re.sub('http(s)?://', '', ref_url.strip())
		reference = "reference:url,%s; "%ref_url
	else:
		reference = ""

	if rule_tag.strip() != "":
		rule_tag = "%s - "%rule_tag
	else:
		rule_tag = ""

	if vtype == "DOMAIN":
		try:
			ip_addr = socket.gethostbyname(value)
		except:
			ip_addr = None

		if ip_addr != None:
			print "[ ] "+value+" :: "+ip_addr
			rules.append('alert udp $HOME_NET any -> %s any (msg:"%s%s - UDP traffic to %s (%s)"; sid:%d; rev:1; classtype:trojan-activity; metadata:impact_flag red; %s)'%(rule_tag, ip_addr, name, ip_addr, value, sid, reference))
			sid += 1
			rules.append('alert tcp $HOME_NET any -> %s any (msg:"%s%s - TCP traffic to %s (%s)"; sid:%d; rev:1; classtype:trojan-activity; metadata:impact_flag red; %s)'%(rule_tag, ip_addr, name, ip_addr, value, sid, reference))
			sid += 1
		else:
			print >> sys.stderr, "[-] %s :: ip address cannot be resolved"%value

		members = value.split(".")
		dns_request = ""
		for m in members:
			dns_request += "|%0.2X|%s"%(len(m),m)
		rules.append('alert udp $HOME_NET any -> any 53 (msg:"%s%s - DNS request for %s"; content:"|01 00 00 01 00 00 00 00 00 00|"; depth:20; offset: 2; content:"%s"; fast_pattern:only; nocase; sid:%d; rev:1; classtype:trojan-activity; metadata:impact_flag red; %s)'%(rule_tag, name, value, dns_request, sid, reference))
		sid += 1

	elif vtype == "URL":
		rules.append('alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"%s%s - Related URL (%s)"; content:"%s"; http_uri; sid:%d; rev:1; classtype:trojan-activity; metadata:impact_flag red; %s)'%(rule_tag, name, value, value, sid, reference))
		sid += 1

	return rules, sid

def blacklist_sql(value, name, vtype="DOMAIN", rule_tag=""):

	if rule_tag.strip() != "":
		rule_tag = "%s - "%rule_tag
	else:
		rule_tag = ""
		
	query = "INSERT INTO domains.blacklist(name, domain_match, match_type) VALUES (\"%s%s\", \"%s\", \"%s\");"%(MySQLdb.escape_string(rule_tag), MySQLdb.escape_string(name), MySQLdb.escape_string(value), MySQLdb.escape_string(vtype))
	return query