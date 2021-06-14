import math

# f1 = open("logs/log_sent.txt", "r")
f2 = open("logs/log_server.txt", "r")

# f1 = f1.readlines()
f2 = f2.readlines()

c = {}
for i in f2:
    vals = i.split(' ')
    t_sent = float(vals[0].split(',')[3])
    flow_type = (int(vals[0].split(',')[0]), int(vals[0].split(',')[1]))
    t_recv = float(vals[1].strip())
    diff = math.ceil((t_recv - t_sent) * 100)
    # print(diff, flow_type[0])
    if diff <= flow_type[0]:
        if flow_type not in c:
            c[flow_type] = 0
        c[flow_type] += 1
print(c)
total = 0
for x in c:
    total += c[x]
print(f"{total}/{len(f2)}")