import socket
import time, os
server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_socket.bind(('', 8125))

try:
    os.remove('logs/log_server.txt')
except:
    print("No log_server found")
    
while True:
    message, address = server_socket.recvfrom(1024)
    message = message.decode("utf-8").split('|')[0].replace(' ', '')
    with open("logs/log_server.txt", "a") as f:
        f.write("{} {}\n".format(message, str(time.time())))