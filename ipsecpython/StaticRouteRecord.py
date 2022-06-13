from socket import socket
from Socket import Socket


class StaticRouteRecord:
    network_ip: str
    network_mask: str
    next_hop: str
    port: int

    def __init__(self, network_ip: str, network_mask: str, next_hop: str, port: int):
        self.network_ip = network_ip
        self.network_mask = network_mask
        self.next_hop = next_hop
        self.port = port

    def __iter__(self):
        return iter((self.network_ip, self.network_mask, self.next_hop, self.port))

    @classmethod
    def fromtuple(cls, t):
        return cls(t[0], t[1], t[2], t[3])

    def totuple(self):
        return self.network_ip, self.network_mask, self.next_hop, self.port
