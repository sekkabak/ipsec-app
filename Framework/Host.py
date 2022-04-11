from scapy.compat import raw
from scapy.layers.inet import IP, TCP
from scapy.layers.ipsec import SecurityAssociation, ESP
from scapy.packet import Raw
from multiprocessing import Process
import pickle
import socket
from Framework.Trigger import Trigger


# TODO implement IKE
# TODO szatkowanie pakietów w tym miejscu żeby bardziej przypominało to IPsec
class Host:
    __key: bytes
    __crypto_algo: str = 'AES-CBC'
    __spi: int
    __src_ip: str
    __src_port: int
    __network_gateway: tuple[str, int]
    __listener: Process
    __send_trigger: Trigger
    __recv_trigger: Trigger

    def __init__(self, key, network_gateway: tuple[str, int], src_port: int, spi: int = 0xdeadbeef):
        self.__key = key
        self.__network_gateway = network_gateway
        self.__src_port = src_port
        self.__spi = spi

        self.__send_trigger = Trigger()
        self.__recv_trigger = Trigger()
        self.__send_trigger.subscribe(self.__sender_process)

    @staticmethod
    def __sender_process(data):
        """This method runs in thread"""
        obj, dst, dst_port, src_port, spi, crypto_algo, key, network_gateway = data

        # socket initialization
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(network_gateway)
        src_ip = s.getsockname()[0]

        # encrypting packet
        sa = SecurityAssociation(ESP, spi=spi, crypt_algo=crypto_algo, crypt_key=key)
        p = IP(src=src_ip, dst=dst)
        p /= TCP(sport=src_port, dport=dst_port)
        p /= Raw(pickle.dumps(obj))
        p = IP(raw(p))
        encrypted_packet = sa.encrypt(p)

        # sending encapsulated packet
        s.sendall(raw(encrypted_packet))
        s.close()

    def send(self, data: any, dst: str, dst_port: int):
        self.__send_trigger.run(
            [data, dst, dst_port, self.__src_port, self.__spi, self.__crypto_algo, self.__key, self.__network_gateway])
