import pickle
import socket
import time
from multiprocessing import Process, Manager, Queue
from typing import Union, Optional

from scapy.compat import raw
from scapy.layers.inet import IP, TCP
from scapy.layers.ipsec import SecurityAssociation, ESP
from scapy.packet import Raw

from StaticRouteRecord import StaticRouteRecord
from Socket import Socket
from Tunnel import Tunnel


class Transceiver:
    __interface: str
    __listen_port: int
    __speaker_port: int
    __ike_port: int = 500
    __static_routes_table: list[StaticRouteRecord]  # (ip, mask, gateway)
    __tunnels: list[Tunnel]

    __listener_queue: "Queue[bytes]"
    __speaker_queue: "Queue[tuple[Socket, bytes]]"

    __listener_process: Process
    __speaker_process: Process

    def __init__(self, interface: str, listen_port: int, speaker_port: int):
        self.__interface = interface
        self.__listen_port = listen_port
        self.__speaker_port = speaker_port
        self.__static_routes_table = []
        self.__tunnels = []

        self.__listener_queue = Queue()
        self.__listener_queue = Queue()
        self.__speaker_queue = Queue()
        self.__start_listener()
        self.__start_speaker()
        self.__start_ike()

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

    def __start_ike(self):
        self.__listener_process = Process(target=self.ike_function,
                                          args=(self.__interface, self.__ike_port, self.__listener_queue,))
        self.__listener_process.start()

    @staticmethod
    def ike_function(interface: str, listen_port: int, qq: "Queue[bytes]"):
        pass
        # server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # server_socket.bind((interface, listen_port))
        #
        # while True:
        #     bob = DHE(14)
        #     ss.sendto(str.encode('Working'), (HOST, PORT))
        #     bob_pub_key = bob.getPublicKey()
        #     bob_pub_key_bytes = bob_pub_key.to_bytes(math.ceil(bob_pub_key.bit_length() / 8), sys.byteorder,
        #                                              signed=False)
        #     # print(bob_pub_key_bytes)
        #     ss.sendto(bob_pub_key_bytes, (HOST, PORT))
        #     alice_pub_key_bytes = ss.recv(2048)
        #     alice_pub_key = int.from_bytes(alice_pub_key_bytes, sys.byteorder, signed=False)
        #     shared_key = bob.update(alice_pub_key)
        #     print("Shared key: ", shared_key)

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
        for ip, mask, gateway in self.__static_routes_table:
            output = ".".join(map(str, [i & m
                                        for i, m in zip(map(int, dest_ip.split(".")),
                                                        map(int, mask.split(".")))]))
            if output == ip:
                return gateway
        raise IndexError("Cannot find network")

    def add_to_static_routes(self, gateway: Socket, mask: str):
        ip = ".".join(map(str, [i & m
                                for i, m in zip(map(int, gateway.ip.split(".")),
                                                map(int, mask.split(".")))]))
        self.__static_routes_table.append(StaticRouteRecord(ip, mask, gateway))

    def send(self, sender: Socket, dst_host: Socket, message: bytes):
        tunnel = self.__has_tunnel_to_network(dst_host)
        # TODO not this way, it only supports 2 routers
        if not tunnel:
            tunnel = self.__try_to_setup_tunnel(dst_host)
        package = self.__encrypt_package(sender, message, tunnel)
        trace = self.__get_trace(tunnel.network_ip)
        self.__speaker_queue.put((trace, package))

    def __get_trace(self, dest_ip: str) -> Socket:
        static_route = next(
            static_route for static_route in self.__static_routes_table if static_route.network_ip == dest_ip)
        return static_route.reach_socket

    # TODO implementation dla UDP
    def __encrypt_package(self, sender: Socket, message: bytes, tunnel: Tunnel) -> bytes:
        sa = SecurityAssociation(ESP, spi=tunnel.spi, crypt_algo=tunnel.crypt_algo, crypt_key=tunnel.crypt_key)
        p = IP(src=sender.ip, dst=tunnel.dst_ip)
        p /= TCP(sport=sender.port, dport=tunnel.dst_port)
        p /= Raw(pickle.dumps(message))

        e = IP(src=self.__interface, dst=tunnel.dst_ip)
        e /= Raw(sa.encrypt(p))
        return raw(e)

    def __decrypt_packet(self, packet: bytes, tunnel: Tunnel):
        sa = SecurityAssociation(ESP, spi=tunnel.spi, crypt_algo=tunnel.crypt_algo, crypt_key=tunnel.crypt_key)
        return sa.decrypt(IP(packet))

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

    def __has_tunnel_to_network(self, dst_host: Socket) -> Optional[Tunnel]:
        try:
            # TODO search for tunnel by SPI
            network = self.find_network(dst_host.ip)
            for tunnel in self.__tunnels:
                if tunnel.network() == network:
                    return tunnel
            # TODO debug
            tunnel = self.__try_to_setup_tunnel(dst_host)
            self.__tunnels.append(tunnel)
            return tunnel
        except IndexError:
            return None

    def __scapy_get_layers(self, packet):
        layers = []
        counter = 0
        while True:
            layer = packet.getlayer(counter)
            if layer is None:
                break
            layers.append(layer)
            counter += 1
        return layers

    def __handle_network_inbound_TCP_traffic(self, message: bytes):
        packet = IP(message)
        # TODO

    def __handle_network_inbound_UDP_traffic(self, message: bytes):
        pass

    def __handle_network_outbound_traffic(self, message: bytes):
        packet = IP(message)

        # check if packets is ment to be here
        if packet.dst == self.__interface:
            # TODO implement normal traffic
            # check if tunnel exist for this source
            tunnel = self.__has_tunnel_to_network(Socket(packet.src, 0))
            if not tunnel:
                # unknown source
                # ignore
                pass
            else:
                data = self.__decrypt_packet(packet.payload.load, tunnel)
                inner_packet: IP = data
                sckt: Socket = Socket(inner_packet.dst, inner_packet.dport)
                self.__speaker_queue.put((sckt, inner_packet.payload.load))

    def __listen_loop_operation(self):
        if not self.__listener_queue.empty():
            message = self.__listener_queue.get()
            try:
                layers = self.__scapy_get_layers(IP(message))
                layers_names = [x.name for x in layers]

                if layers_names == ['IP', 'TCP', 'Raw']:
                    self.__handle_network_inbound_TCP_traffic(message)
                if layers_names == ['IP', 'UDP', 'Raw']:
                    self.__handle_network_inbound_UDP_traffic(message)
                elif layers_names == ['IP', 'Raw']:
                    self.__handle_network_outbound_traffic(message)
            except:
                pass

    def start(self):
        try:
            while True:
                self.__listen_loop_operation()
        except KeyboardInterrupt:
            self.__speaker_process.kill()
            self.__listener_process.kill()

    def test(self, sck: Socket, message: bytes, delay: int = 5):
        try:
            while True:
                time.sleep(delay)
                self.send(Socket('0.0.0.0', 00000), sck, message)
        except KeyboardInterrupt:
            self.__speaker_process.kill()
            self.__listener_process.kill()
