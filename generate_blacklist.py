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
import gen
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
    BCKLST_FILE = conf.BCKLST_FILE
except:
    BCKLST_FILE = "blacklist.sql"
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
suricata_rules = ""
blacklist_sql  = ""
sid += 1

print "[+] Generating rules"
try:
    with open(IN_FILE, "r") as f_domains:
        for line in f_domains:
            line = line.strip()
            if line == "" or line.startswith("#"):
                rules.append(line)
                continue

            # Cut the line to extract the different fields
            (name, value, ref_url, junk) = line.split(';', 3)
            name                         = name.strip()
            value                        = value.strip()
            ref_url                      = ref_url.strip()
            
            if value == "":
                continue

            if value.startswith("/"):
                vtype = "URL"
            else:
                vtype = "DOMAIN"

            # Generate the Suricata rules.
            # The function returns the new available SID and an array containing
            # the new Suricata rules.
            (rules, sid) = gen.suricata_rule(value, sid, name, ref_url, vtype)
            suricata_rules += "\n".join(rules) + "\n"

            rules = gen.blacklist_sql(value, name, vtype)
            blacklist_sql += rules + "\n"
except Exception, e:
    print >> sys.stderr, "[!] Cannot read <%s>"%IN_FILE
    print >> sys.stderr, e
    sys.exit(1)

#############################################
#       Writing Rules
print "[+] Writing suricata file"
try:
    with open(OUT_FILE, "a") as f_rules:
        f_rules.write(suricata_rules)
    print "[ ] File written"
except:
    print "[!] Cannot write <%s>"%OUT_FILE
    sys.exit(1)

print "[+] Writing blacklist SQL file"
try:
    with open(BCKLST_FILE, "a") as f_rules:
        f_rules.write(blacklist_sql)
    print "[ ] File written"
except:
    print "[!] Cannot write <%s>"%BCKLST_FILE
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
