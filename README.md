bl2ru
=====

Simple script for Snort rules generation from blacklist (1 FQDN by line, comments using #).

Creates 3 rules :
- UDP communication rule ($HOME_NET any -> IP any)
- TCP communication rule
- DNS request rule
