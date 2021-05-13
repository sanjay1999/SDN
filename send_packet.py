from scapy.all import *
import sys

args = sys.argv[1:]
print(args[1], args[0], args[0])
pkt = IP(dst=args[1], src=args[0], tos=144)/UDP(dport=8125)/args[2]
send(pkt, count=1)