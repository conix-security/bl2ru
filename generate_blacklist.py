#!/usr/bin/python
# Copyright 2013 Conix Security, Adrien Chevalier
# adrien.chevalier@conix.fr
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

print "EDIT THIS FILE PLZ"
exit(1)


#########################################################################
# parameters
out_file = "blacklisted-domains.rule"       # rules file
in_file = "blacklist.txt"                   # blacklist file
sid = 1510000                               # default SID
ssh_deploy = True                           # deploy through SSH, False to disable ?

# SSH servers (ssh deployment)
ssh_serverz = []
# serverX = [HOST,PORT,USERNAME,PASSWORD,REMOTE_PATH]

# SSH servers examples:
# server1 = ["127.0.0.1",22,"null","PASSWORD","/home/null/"]
# ssh_serverz.append(server1)
# server2 = ["127.0.0.1",22,"null","PASSWORD","/tmp/"]
# ssh_serverz.append(server2)

#########################################################################


if ssh_deploy:
    try:
        import paramiko
        ssh_deploy = True
    except ImportError:
        print "[!] Paramiko lib not found, install with <pip install paramiko>"
        print "\t[-] Disabling SSH rules deployment"
        ssh_deploy = False

print "[+] Getting SID"
# get last SID
try:
    fhandle = open(out_file,"r")
    
    # read last not empty line
    fhandle.seek(-2, 2)                # Jump to the second last byte.
    last = ""
    while last == "":
        while fhandle.read(1) != "\n": # Get to beggining of the line
            fhandle.seek(-2, 1)        # 
        last = fhandle.readline()      # Read line.
        last = last.strip()
        if last[0] == "#":             # Empty line check
            last = ""
        if last == "":
            f.seek(-2,1)               # Empty => loop
    fhandle.close()

    # get SID
    pos = last.find("sid:")
    if pos != -1:
        last = last[pos+4:]
        pos = last.find(";")
        strsid = last[:pos].strip()
        if strsid != "":
            sid = int(strsid)
            print "\t[-] <"+out_file+"> parsed, starting SID from "+str(sid)
    else:
        print "\t[!] <"+out_file+"> parsing error, exiting."
        exit(1)
except IOError:
    sid = 1510000
    print "\t[-] <"+out_file+"> not found, starting SID from 1510000"

print "[+] Generating rules"
# get data
try:
    fhandle = open(in_file,"r")
    fdata = fhandle.read()
    fhandle.close()
except IOError:
    print "\t[!] Cannot read <"+in_file+">"
    exit(1)

rulez = ""
flines = fdata.split("\n")
for fqdn in flines:
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
        print "\t[-] "+fqdn+" :: "+ip_addr
        rulez = rulez+'alert udp $HOME_NET any -> '+ip_addr+' any (msg:"SPAM Campaign UDP Communication FOR '+ip_addr+' ('+fqdn+')"; classtype:trojan-activity; sid:'+str(sid)+'; rev:1; metadata:impact_flag red;)\n'
        sid = sid+1
        rulez = rulez+'alert tcp $HOME_NET any -> '+ip_addr+' any (msg:"SPAM Campaign TCP Communication FOR '+ip_addr+' ('+fqdn+')"; classtype:trojan-activity; sid:'+str(sid)+'; rev:1; metadata:impact_flag red;)\n'
        sid = sid+1
    else:
        print "\t[-] "+fqdn+" :: ip address not resolved"
    
    members = fqdn.split(".")
    dns_request = ""
    for m in members:
        dns_request = dns_request+"|"+str(len(m))+"|"+m
    rulez = rulez+'alert udp $HOME_NET any -> any 53 (msg:"SPAM Campaign DNS REQUEST FOR '+fqdn+' UDP"; content:"|01 00 00 01 00 00 00 00 00 00|"; depth:20; offset: 2; content:"'+dns_request+'"; fast_pattern:only; nocase; classtype:trojan-activity; sid:'+str(sid)+'; rev:1; metadata:impact_flag red;)"\n'
    sid = sid+1

print "[+] Writing file"
try:
    fhandle = open(out_file,"a")
    fhandle.write(rulez)
    fhandle.close()
    print "\t[-] File written"
except IOError:
    print "\t[!] Cannot write <"+out_file+">"
    exit(1)

if ssh_deploy:
    print "[+] SSH deployment"
    for server in ssh_serverz:
        ssh_server = server[0]
        ssh_port = server[1]
        ssh_user = server[2]
        ssh_password = server[3]
        ssh_remote_path = server[4]+"/"+os.path.basename(out_file)
        try:
            client = paramiko.SSHClient()
            client.load_system_host_keys()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(ssh_server, ssh_port, ssh_user, ssh_password)
            sftp = paramiko.SFTPClient.from_transport(client.get_transport())
            sftp.put(out_file,ssh_remote_path)
            sftp.close()
            client.close()
            print "\t[-] Rules dispatched on <"+ssh_server+">"
        except Exception,e:
            print "\t[!] Rule dispatching error on <"+ssh_server+">: %s" %e

print "[+] Finished"
