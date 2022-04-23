from Socket import Socket


class StaticRouteRecord:
    network_ip: str
    network_mask: str
    reach_socket: Socket

    def __init__(self, network_ip: str, network_mask: str, reach_socket: Socket):
        self.network_ip = network_ip
        self.network_mask = network_mask
        self.reach_socket = reach_socket

    def __iter__(self):
        return iter((self.network_ip, self.network_mask, self.reach_socket))

    @classmethod
    def fromtuple(cls, t: tuple[str, str, Socket]):
        return cls(t[0], t[1], t[2])

    def totuple(self) -> tuple[str, str, Socket]:
        return self.network_ip, self.network_mask, self.reach_socket
