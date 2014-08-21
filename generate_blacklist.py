#!/usr/bin/python
# Copyright 2013 Conix Security
# adrien.chevalier@conix.fr
# alexandre.deloup@conix.fr
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
import socket
import os
import sys
import os.path

#############################################
#       Load configuration
try:
    import conf
except ImportError:
    print >> sys.stderr, "[!] Error importing conf.py."
    print >> sys.stderr, "[ ] You can create your configuration file from the default one:"
    print >> sys.stderr, "[ ] $ cp conf.py.sample conf.py && vim conf.py"
    sys.exit(1)

try:
    OUT_FILE = conf.OUT_FILE
except:
    OUT_FILE = "blacklisted-domains.rules"
try:
    IN_FILE = conf.IN_FILE
except:
    IN_FILE = "blacklist.txt"
try:
    SID_LOG_FILE = conf.SID_LOG_FILE
except:
    SID_LOG_FILE = ".sid_log_file"
try:
    SSH_DEPLOY = conf.SSH_DEPLOY
except:
    SSH_DEPLOY = False
try:
    SSH_SERVERS = conf.SSH_SERVERS
except:
    SSH_SERVERS = ()

#############################################
#       SSH Deployement requirement
if SSH_DEPLOY:
    try:
        import paramiko
    except ImportError:
        print >> sys.stderr, "[!] Error importing Paramiko library."
        print >> sys.stderr, "[ ] Install it with <pip install paramiko>"
        print >> sys.stderr, "[-] Disabling SSH rules deployment"
        SSH_DEPLOY = False

#############################################
#       Latest SID
print "[+] Getting SID"
# get last SID    
try:
    with open(SID_LOG_FILE, "r") as f_sid_log_file:
        line = f_sid_log_file.readline()
        sid = int(line)
except:
    sid = 1510000
    print >> sys.stderr, "[-] <%s> not found, starting SID from 1510000"%SID_LOG_FILE

#############################################
#       Generating Rules
rules = ""
sid += 1
print "[+] Generating rules"
try:
    with open(IN_FILE, "r") as f_domains:
        rules = ""
        for fqdn in f_domains:
            pos = fqdn.find("#")
            if pos != -1:
                fqdn = fqdn[:pos]
            
            fqdn = fqdn.strip()
            
            if fqdn == "":
                continue
            try:
                ip_addr = socket.gethostbyname(fqdn)
            except:
                ip_addr = None

            if ip_addr != None:
                print "[ ] "+fqdn+" :: "+ip_addr
                rules += 'alert udp $HOME_NET any -> '+ip_addr+' any (msg:"SPAM Campaign UDP Communication FOR '+ip_addr+' ('+fqdn+')"; classtype:trojan-activity; sid:'+str(sid)+'; rev:1; metadata:impact_flag red;)\n'
                sid += 1
                rules += 'alert tcp $HOME_NET any -> '+ip_addr+' any (msg:"SPAM Campaign TCP Communication FOR '+ip_addr+' ('+fqdn+')"; classtype:trojan-activity; sid:'+str(sid)+'; rev:1; metadata:impact_flag red;)\n'
                sid += 1
            else:
                print >> sys.stderr, "[-] %s :: ip address not resolved"%fqdn
            
            members = fqdn.split(".")
            dns_request = ""
            for m in members:
                dns_request += "|%02d|%s"%(len(m),m)
            rules += 'alert udp $HOME_NET any -> any 53 (msg:"SPAM Campaign DNS REQUEST FOR '+fqdn+' UDP"; content:"|01 00 00 01 00 00 00 00 00 00|"; depth:20; offset: 2; content:"'+dns_request+'"; fast_pattern:only; nocase; classtype:trojan-activity; sid:'+str(sid)+'; rev:1; metadata:impact_flag red;)\n'
            sid += 1
except:
    print >> sys.stderr, "[!] Cannot read <%s>"%IN_FILE
    sys.exit(1)

#############################################
#       Writing Rules
print "[+] Writing file"
try:
    with open(OUT_FILE, "a") as f_rules:
        f_rules.write(rules)
    print "[ ] File written"
except:
    print "[!] Cannot write <%s>"%OUT_FILE
    sys.exit(1)

if SSH_DEPLOY:
    print "[+] SSH deployment"
    for server in SSH_SERVERS:
        ssh_server      = server[0]
        ssh_port        = server[1]
        ssh_user        = server[2]
        ssh_password    = server[3]
        ssh_remote_path = os.path.join(server[4], os.path.basename(OUT_FILE))
        try:
            client = paramiko.SSHClient()
            client.load_system_host_keys()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(ssh_server, ssh_port, ssh_user, ssh_password)
            sftp = paramiko.SFTPClient.from_transport(client.get_transport())
            sftp.put(OUT_FILE, ssh_remote_path)
            sftp.close()
            client.close()
            print "[ ] Rules dispatched on <%s>"%ssh_server
        except Exception,e:
            print "[!] Rule dispatching error on <%s>: %s" %(ssh_server, e)

#############################################
#       Logging max sid
print "[+] Writing Last SID"
with open(SID_LOG_FILE, "w") as f_sid:
    f_sid.write("%d"%(sid-1))

print "[+] Finished!"
