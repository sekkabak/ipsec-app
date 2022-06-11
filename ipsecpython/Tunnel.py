from Socket import Socket


class Tunnel:
    spi: int
    dst_ip: str
    network_ip: str
    network_port: int
    crypt_algo: str
    crypt_key: bytes

    def network(self) -> Socket:
        return Socket(self.network_ip, self.network_port)
