#!/usr/bin/python


import sys


from scapy.all import *

clientProbes=set()



def PacketHandler(pkt):
 if pkt.haslayer(Dot11ProbeReq):
  if len(pkt.info)>0 :  #eliminating null probe requests !
   testcase=pkt.addr2+ '---' + pkt.info
   if testcase not in clientProbes:
    clientProbes.add(testcase)
    print "New Probe Found "+ pkt.addr2+" "+pkt.info

sniff(iface=sys.argv[1],count=int(sys.argv[2]),prn=PacketHandler)
