from scapy.all import *

pkt = IP(dst="10.0.0.1", src="10.0.0.2", tos=144)/UDP()
send(pkt, count=1)  # 20 packets / second
