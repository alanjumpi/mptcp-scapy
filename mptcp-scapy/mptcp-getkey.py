# mptcp-getkey.py
#
# This is a proof of concept to get hash send/receive keys from MPTCP packet
#
#

#!/usr/bin/python -tt

from scapy.all import *
import sys
import re

# Parsing packet function

def parse(pkt):
	if TCP in pkt:
		mptcp = str(pkt.getlayer("TCP").options)
		match = re.search(r'MP_CAPABLE', mptcp)
		match2 = re.search(r'snd_key=(\w+)', mptcp)
		match3 = re.search(r'rcv_key=(\w+)', mptcp)
		if match: 
			print "send key: " + match2.group(1)
		elif match3:
			print "receive key: " + match3.group(1)
	

# Reading packets from a pcap file

pkts = rdpcap(sys.argv[1])
for pkt in pkts:
	parse(pkt)

