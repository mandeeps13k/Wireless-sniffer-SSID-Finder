#!/usr/bin/python

import sys

from scapy.all import *

ssids=set()


def PacketHandler(pkt):
 if pkt.haslayer(Dot11Beacon):
  if pkt.info and pkt.info not in ssids:
   print len(ssids),pkt.addr2,pkt.info
   ssids.add(pkt.info)

sniff(iface=sys.argv[1],count=int(sys.argv[2]),prn=PacketHandler)


