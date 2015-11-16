#!/usr/bin/env python
__author__ = "nikita kozlov <nikita@gandi.net> (GANDI)"
__copyright__ = "GANDI SAS"
__version__ = "0.1"

import socket
import re
import json
try:
    from collections import OrderedDict
except ImportError:
    import ordereddict

import snmp_passpersist as snmp

oid_base = '.1.3.6.1.4.1.26384'

def get_stats(so_path):
    so = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    so.connect(so_path)
    so.send("stats -j\r\n")
    data = ''
    while True:
        buf = so.recv(8000)
        data += buf
        if len(data) > 20 and data[-6:].startswith("pktj>") :
            break
    so.close()
    return json.loads(re.sub(r'pktj>|stats -j', '', data))

def update():
    data = get_stats('/var/run/pktj.1')
    pp.add_cnt_64bit("1.1.1.1.0.0", int(data['total']['rx']))
    pp.add_cnt_64bit("1.1.1.1.1.0", int(data['total']['tx']))
    pp.add_cnt_64bit("1.1.1.2.0.0", int(data['total']['drop']))
    pp.add_cnt_64bit("1.1.1.2.1.0", int(data['total']['acl_drop']))
    pp.add_cnt_64bit("1.1.1.2.2.0", int(data['total']['rate_drop']))
    pp.add_cnt_64bit("1.1.1.3.0.0", int(data['total']['kni_rx']))
    pp.add_cnt_64bit("1.1.1.3.1.0", int(data['total']['kni_tx']))
    pp.add_cnt_64bit("1.1.1.3.2.0", int(data['total']['kni_drop']))

pp = snmp.PassPersist(oid_base)
pp.start(update, 10)
