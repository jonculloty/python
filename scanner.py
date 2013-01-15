#!/usr/bin/python

# We have an iptable rule to prepend HACKER to all SYN connections on port 22.
# Just after that the connection is dropped
# -A INPUT -p tcp -m tcp --dport 22 -j LOG --log-prefix "HACKER:  "

# This script finds all these entries and counts SYN attempts per IP
#

import re
import urllib2
from xml.dom import minidom

class Scanner:

    """ Check Ubuntu logs for strange things """

    def CheckBruteForce(self):
        pattern = re.compile('SRC=\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}')
        ips = {}
        f = open('/var/log/kern.log', 'r')
        for line in f:
            if "HACKER" in line: 
                ipl = pattern.findall(line)
                ipstr = ipl[0].split("=")[1]

                if ipstr in ips:
                    ips[ipstr] = ips[ipstr] + 1
                else:
                    ips[ipstr]=1
        return ips

    def GetLocation(self, ip):
        url = "http://www.geoplugin.net/xml.gp?ip=%s" % ip
        usock = urllib2.urlopen(url) 
        xmldoc = minidom.parse(usock)

        for element in xmldoc.getElementsByTagName('geoplugin_countryName'):
            return element.firstChild.nodeValue

    def PrintReport(self, ips):
        for key, value in ips.items():
            country = self.GetLocation(key)
            print "%-20s %-5s %s" % (key,value,country)

if __name__ == "__main__":

    x = Scanner()
    susIPs = x.CheckBruteForce()
    x.PrintReport(susIPs)
