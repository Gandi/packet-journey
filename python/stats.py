import time
import socket
import client



s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect('/tmp/truc.sock')

client = client.RouterClient(s)


old_opackets = 0
old_ipackets = 0
old_ierrors = 0
old_ibadcrc = 0
old_ibadlen = 0
old_imcasts = 0
old_ibytes = 0

try:
    while True:
        resp = client.get_stats(0)
        opackets = resp.opackets
    
        resp = client.get_stats(1)
        ipackets = resp.ipackets
        ierrors = resp.ierrors
        ibadcrc = resp.ibadcrc
        ibadlen = resp.ibadlen
        ibytes = resp.ibytes
        imcasts = resp.imcasts

        print "ipackets", ipackets - old_ipackets
        print "ierrors", ierrors - old_ierrors
        print "ibadcrc", ibadcrc - old_ibadcrc
        print "ibadlen", ibadlen - old_ibadlen
        print "imcasts", imcasts - old_imcasts
        print "ibytes", (ibytes - old_ibytes) * 8 / 1000000
        print "opackets", opackets - old_opackets

        old_ipackets = ipackets
        old_ierrors = ierrors
        old_ibadcrc = ibadcrc
        old_ibadlen = ibadlen
        old_imcasts = imcasts
        old_ibytes = ibytes
        old_opackets = opackets

        time.sleep(1)

finally:
    s.close()


