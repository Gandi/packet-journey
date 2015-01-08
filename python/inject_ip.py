import time
import socket
import client



s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect('/tmp/truc.sock')

client = client.RouterClient(s)

j = 0

try:
    for i in xrange(0,pow(2,32), 8192):
        ip = i
        length = 19
        via = ip
        port = 0

        client.add_route4(ip, length, via, port)
        j += 1
        if j % 10000 == 0:
            print j
finally:
    s.close()


