from scapy.compat import raw
from scapy.layers.inet import IP, TCP
from scapy.layers.ipsec import SecurityAssociation, ESP
from scapy.packet import Raw
import pickle
import socket


class Host:
    key: bytes
    crypto_algo: str = 'AES-CBC'
    spi: int
    src_ip: str
    src_port: int
    network_gateway: tuple[str, int]

    def __init__(self, key, network_gateway: tuple[str, int], spi: int = 0xdeadbeef):
        self.key = key
        self.network_gateway = network_gateway
        self.spi = spi

    def __create_esp_packet(self, data: bytes, dst: str, dst_port: int):
        sa = SecurityAssociation(ESP, spi=self.spi, crypt_algo=self.crypto_algo, crypt_key=self.key)
        p = IP(src=self.src_ip, dst=dst)
        p /= TCP(sport=self.src_port, dport=dst_port)
        p /= Raw(data)
        p = IP(raw(p))
        return sa.encrypt(p)

    @staticmethod
    def __recvall(sock, n):
        # Helper function to recv n bytes or return None if EOF is hit
        data = bytearray()
        while len(data) < n:
            packet = sock.recv(n - len(data))
            if not packet:
                return None
            data.extend(packet)
        return data

    def send(self, data: any, dst: str, dst_port: int):
        # socket initialization
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.src_ip = s.getsockname()[0]
        self.src_port = s.getsockname()[1]

        # prepare data
        obj = pickle.dumps(data)
        encrypted_packet = self.__create_esp_packet(obj, dst, dst_port)

        s.connect(self.network_gateway)
        s.sendall(raw(encrypted_packet))
        s.close()

    def recv(self):
        pass