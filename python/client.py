import router_pb2 as proto

import logging
log = logging.getLogger(__name__)
hostname = 'localhost'
port = 1234


import struct
import socket

class ProtobufClient(object):
    def __init__(self, sock):
        self.sock = sock
        self.request_id = 0

    def request(self, method_index, request, response_class):
        msg = request.SerializeToString()
        self.sock.sendall(struct.pack('<III', method_index, len(msg), self.request_id) + msg)

        (status_code, method_index, message_length, request_id) = struct.unpack('<IIII', self.sock.recv(16))
        self.request_id += 1

        if (status_code != 0):
            raise Exception('something bad occured')

        resp = response_class()
        if message_length>0:
            resp.ParseFromString(self.sock.recv(message_length))

        return resp


class RouterClient(ProtobufClient):
    def get_stats(self, port_id):
        req = proto.GetIfaceRequest()
        req.portid = port_id
        return self.request(1, req, proto.GetIfaceResult)

    def add_route4(self, ip, length, via, port):
        req = proto.AddRoute4Request()
        req.cidr.ip = ip
        req.cidr.length = length
        req.via = via
        req.port = port
        return self.request(0, req, proto.AddRoute4Result)

