class Socket:
    ip: str
    port: int

    def __init__(self, ip: str, port: int):
        self.ip = ip
        self.port = port

    @classmethod
    def fromtuple(cls, t):
        return cls(t[0], t[1])

    def totuple(self):
        return self.ip, self.port
