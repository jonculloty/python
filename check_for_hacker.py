#!/usr/bin/python

# We have an iptable rule to prepend HACKER to all SYN connections on port 22.
# Just after that the connection is dropped
# -A INPUT -p tcp -m tcp --dport 22 -j LOG --log-prefix "HACKER:  "

# This script finds all these entries and counts SYN attempts per IP
#

import re

ips = {}
pattern = re.compile('SRC=\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}')

f = open('/var/log/kern.log', 'r')
for line in f:
    if "HACKER" in line: 
        ipl = pattern.findall(line)
        ipstr = ipl[0].split("=")[1]

        if ipstr in ips:
            ips[ipstr] = ips[ipstr] + 1
        else:
            ips[ipstr]=1

for key, value in ips.items():
    print "%s (%s)" % (key,value)
