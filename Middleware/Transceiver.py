import pickle
import socket
import time
from multiprocessing import Process, Manager, Queue
from typing import Union

from scapy.compat import raw
from scapy.layers.inet import IP, TCP
from scapy.layers.ipsec import SecurityAssociation, ESP
from scapy.packet import Raw

from Middleware.ArpRecord import ArpRecord
from Middleware.Socket import Socket
from Middleware.Tunnel import Tunnel


class Transceiver:
    """
    This will contain network IP with MASK and gateway as (IP,PORT) to determinate target
    """
    __interface: str
    __listen_port: int
    __speaker_port: int
    __arp_table: list[ArpRecord]  # (ip, mask, gateway)
    # __local_network_database: list
    __tunnels: list[Tunnel]

    __manager: Manager
    __listener_queue: "Queue[bytes]"
    __speaker_queue: "Queue[tuple[Socket, bytes]]"

    __listener_process: Process
    __speaker_process: Process

    def __init__(self, interface: str, listen_port: int, speaker_port: int):
        self.__interface = interface
        self.__listen_port = listen_port
        self.__speaker_port = speaker_port
        self.__arp_table = []
        self.__tunnels = []

        self.__manager = Manager()
        self.__listener_queue = Queue()
        self.__speaker_queue = Queue()
        self.__start_listener()
        self.__start_speaker()

    def __start_listener(self):
        self.__listener_process = Process(target=self.listener_function,
                                          args=(self.__interface, self.__listen_port, self.__listener_queue,))
        self.__listener_process.start()

    @staticmethod
    def listener_function(interface: str, listen_port: int, qq: "Queue[bytes]"):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_socket.bind((interface, listen_port))

        while True:
            message, address = server_socket.recvfrom(1024)
            qq.put(message)

    def __start_speaker(self):
        self.__speaker_process = Process(target=self.speaker_function,
                                         args=(self.__interface, self.__speaker_port, self.__speaker_queue))
        self.__speaker_process.start()

    @staticmethod
    def speaker_function(interface: str, speaker_port: int, qq: "Queue[tuple[Socket, bytes]]"):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_socket.bind((interface, speaker_port))
        while True:
            if not qq.empty():
                # example data (("127.0.0.1",7070), "test")
                address, data = qq.get()
                server_socket.sendto(data, address.totuple())

    def find_network(self, dest_ip: str) -> Socket:
        """This will return Transceiver (IP,PORT) for given IP"""
        for ip, mask, gateway in self.__arp_table:
            output = ".".join(map(str, [i & m
                                        for i, m in zip(map(int, dest_ip.split(".")),
                                                        map(int, mask.split(".")))]))
            if output == ip:
                return gateway
        raise IndexError("Cannot find network")

    def add_to_arp(self, gateway: Socket, mask: str):
        ip = ".".join(map(str, [i & m
                                for i, m in zip(map(int, gateway.ip.split(".")),
                                                map(int, mask.split(".")))]))
        self.__arp_table.append(ArpRecord(ip, mask, gateway))

    def send(self, dst_host: Socket, message: bytes):
        tunnel = self.__has_tunnel_to_network(dst_host)
        if not tunnel:
            tunnel = self.__try_to_setup_tunnel(dst_host)
        package = self.__encrypt_package(message, tunnel)
        trace = self.__get_trace(tunnel.network_ip)
        self.__speaker_queue.put((trace, package))

    def __get_trace(self, dest_ip: str) -> Socket:
        arp_record = next(arp_record for arp_record in self.__arp_table if arp_record.network_ip == dest_ip)
        return arp_record.reach_socket

    def __encrypt_package(self, message: bytes, tunnel: Tunnel) -> bytes:
        sa = SecurityAssociation(ESP, spi=tunnel.spi, crypt_algo=tunnel.crypt_algo, crypt_key=tunnel.crypt_key)
        p = IP(src=self.__interface, dst=tunnel.dst_ip)
        p /= TCP(sport=self.__listen_port, dport=tunnel.dst_port)
        p /= Raw(pickle.dumps(message))
        p = IP(raw(p))
        return raw(sa.encrypt(p))

    def __try_to_setup_tunnel(self, dst_host: Socket) -> Tunnel:
        tunnel = Tunnel()
        network = self.find_network(dst_host.ip)
        if not network:
            raise Exception("Cannot reach that network")
        tunnel.network_ip = network.ip
        tunnel.network_port = network.port
        tunnel.dst_ip = dst_host.ip
        tunnel.dst_port = dst_host.port

        # TODO add Diffie-Hellman
        tunnel.crypt_algo = 'AES-CBC'
        tunnel.spi = 0xdeadbeef
        tunnel.crypt_key = b'aaaaaaaaaaaaaaaa'

        return tunnel

    def __has_tunnel_to_network(self, dst_host: Socket) -> Union[Tunnel, bool]:
        try:
            network = self.find_network(dst_host.ip)
            for tunnel in self.__tunnels:
                if tunnel.network() == network:
                    return tunnel
        except IndexError:
            return False

    def start(self):
        try:
            while True:
                if not self.__listener_queue.empty():
                    # TODO need to check if this packet is for you or you should pass it further
                    # sa.decrypt(e)
                    message = self.__listener_queue.get()
                    print(message)
        except KeyboardInterrupt:
            self.__speaker_process.kill()
            self.__listener_process.kill()

    def test(self, sck: Socket, message: bytes, delay: int = 5):
        try:
            while True:
                time.sleep(delay)
                self.send(sck, message)
        except KeyboardInterrupt:
            self.__speaker_process.kill()
            self.__listener_process.kill()
