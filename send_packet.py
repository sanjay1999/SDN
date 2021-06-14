from scapy.all import *
import sys, os, random, string, time
# from ryu.lib.packet import packet as ryuPacket
def gen_random(n):
    return ''.join(random.choices(string.digits + string.digits, k=n))

class CustomPacket(Packet):
    name = "CustomPacket"
    fields_desc = [LongField("bw", 5), LongField("delay", 5)]

args = sys.argv[1:]

# print(int(args[0]))

C = int(args[0])
p_no = 1
# f = open("logs/log_sent.txt", "w")

try:
    os.remove('logs/log_server.txt')
except:
    print("No log_server found")

def send_flow(x, p):
    global p_no
    total = C * p
    while total > 0:
        cnt = random.randint(1, total) % 20
        t = time.time()
        payload = f"{x},{t} | custom {str(gen_random(1400))}"
        pkt = IP(dst='10.0.0.2', src='10.0.0.1', tos=144)/UDP(dport=8125)/payload
        send(pkt, count=cnt)
        # f.write(f"{p_no} {str(t)}\n")
        p_no += 1
        total -= cnt
        # time.sleep(random.uniform(0, 5/C))

send_flow("70,5,1", 0.5)
send_flow("80,6,1", 0.3)
send_flow("100,8,1", 0.2)