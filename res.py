import math

# f1 = open("logs/log_sent.txt", "r")
f2 = open("logs/log_server.txt", "r")

# f1 = f1.readlines()
f2 = f2.readlines()

# time_sent = {}
# time_recv = {}
# flow_type = {}
# for i in f1:
#     vals = i.split(' ')
#     time_sent[int(vals[0])] = float(vals[1].strip())

# for i in f2:
#     vals = i.split(' ')
#     no = int(vals[0].split(',')[2])
#     flow_type[no] = (int(vals[0].split(',')[0]), int(vals[0].split(',')[1]))
#     time_recv[no] = float(vals[1].strip())

# c = {}
# for i in range(1, len(time_sent) + 1):
#     try:
#         diff = time_recv[i] - time_sent[i]
#         print(i, flow_type[i], diff)
#         t = math.ceil(diff * 1000)
#         if t <= flow_type[i][0]:
#             if flow_type[i] not in c:
#                 c[flow_type[i]] = 0
#             c[flow_type[i]] += 1
#     except:
#         print("Dropped")

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