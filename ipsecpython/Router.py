import errno
import fcntl
import os
import pickle
import socket
import sys
import time
from multiprocessing import Process, Manager, Queue
from typing import Union, Optional

from scapy.compat import raw
from scapy.layers.inet import IP, TCP
from scapy.layers.ipsec import SecurityAssociation, ESP
from scapy.packet import Raw
from IKE import IKE

from StaticRouteRecord import StaticRouteRecord
from Socket import Socket
from Tunnel import Tunnel
from DiffieHellman import DiffieHellman

import logging
logger = logging.getLogger("router")
logger.setLevel(logging.DEBUG)

class Router:
    __interface: str
    __listen_port: int
    __speaker_port: int
    __static_routes_table: list[StaticRouteRecord]  # (ip, mask, gateway)
    __tunnels: list[Tunnel]

    __listener_queue: "Queue[bytes]"
    __speaker_queue: "Queue[tuple[Socket, bytes]]"

    __listener_process: Process
    __speaker_process: Process

    __ike: IKE

    def __init__(self, interface: str, listen_port: int, speaker_port: int):
        self.__interface = interface
        self.__listen_port = listen_port
        self.__speaker_port = speaker_port
        self.__static_routes_table = []
        self.__tunnels = []

        self.__ike = IKE(interface, self)

        self.__listener_queue = Queue()
        self.__speaker_queue = Queue()
        self.__start_listener()
        self.__start_speaker()

    def __start_listener(self):
        self.__listener_process = Process(target=self.__listener_function,
                                          args=(self.__interface, self.__listen_port, self.__listener_queue,))
        self.__listener_process.start()

    @staticmethod
    def __listener_function(interface: str, listen_port: int, qq: "Queue[bytes]"):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_socket.bind((interface, listen_port))

        while True:
            message, address = server_socket.recvfrom(1024)
            qq.put(message)

    def __start_speaker(self):
        self.__speaker_process = Process(target=self.__speaker_function,
                                         args=(self.__interface, self.__speaker_port, self.__speaker_queue))
        self.__speaker_process.start()

    @staticmethod
    def __speaker_function(interface: str, speaker_port: int, qq: "Queue[tuple[Socket, bytes]]"):
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
        self.__speaker_queue.put((trace.totuple(), package))

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

    # def __listen_loop_operation(self):
    #     if not self.__listener_queue.empty():
    #         message = self.__listener_queue.get()
    #         try:
    #             layers = self.__scapy_get_layers(IP(message))
    #             layers_names = [x.name for x in layers]

    #             if layers_names == ['IP', 'TCP', 'Raw']:
    #                 self.__handle_network_inbound_TCP_traffic(message)
    #             if layers_names == ['IP', 'UDP', 'Raw']:
    #                 self.__handle_network_inbound_UDP_traffic(message)
    #             elif layers_names == ['IP', 'Raw']:
    #                 self.__handle_network_outbound_traffic(message)
    #         except:
    #             pass
    
    def __print_help(self):
        print("Help options")
        print("quit - turn off router")
        print("help - shell options")
        print("clear - clears console")
        print("status - show router status")
        print("traces - list of static routing")
        print("tunnels - list tunnels")
        print("tunnels_info - list tunnels with its data")
        print("create_tunnel {address} - creates IPsec tunnel with given router")
        print("ping {address} {port} - pings router on specific address and port")
        print("")
        
    def __print_status(self):
        print(f"IP: {self.__interface}")
        print(f"IKE port: 500")
        print(f"listener port: {self.__listen_port}")
        print(f"sender port: {self.__speaker_port}")
        print("")
        
    def __clear_console(self):
        os.system('cls' if os.name=='nt' else 'clear')
        
    def __list_of_traces(self):
        for route in self.__static_routes_table:
            print(f"IP: {route.network_ip} {route.network_mask} to {route.reach_socket.ip}:{route.reach_socket.port}")
        print("")
        
    def __list_tunnels(self):
        i = 0
        for tunnel in self.__tunnels:
            print(f"Tunnel{i} SPI: {tunnel.spi}")
            i+=1
        print("")
            
    def __list_tunnels_with_data(self):
        i = 0
        for tunnel in self.__tunnels:
            print(f"Tunnel{i}")
            print(f"\tSPI: {tunnel.spi}")
            print(f"\tNetwork_IP: {tunnel.network_ip}")
            print(f"\tNetwork_PORT: {tunnel.network_port}")
            print(f"\tDestination_IP: {tunnel.dst_ip}")
            print(f"\tDestination_PORT: {tunnel.dst_port}")
            print(f"\tKey: {tunnel.crypt_key}")
            print(f"\tAlgorithm: {tunnel.crypt_algo}")
            i+=1
        print("")
    
    def __create_tunnel(self, ip):
        s = self.__get_trace(ip)
        spi, crypt_algo, crypt_key = self.__ike.negotiate_keys(s)
        print(f"spi: {spi}")
        print(f"crypt_algo: {crypt_algo}")
        print(f"crypt_key: {crypt_key}")
        
    def __program_loop(self):
        print("Welcome in Router emulator shell")
        print("type help for options")
        
        while True:
            choice = input("$ ")
            if choice in ('exit', 'quit'):
                self.stop_router()
            elif choice in ('help', 'h', '?'):
                self.__print_help()
            elif choice in ('status'):
                self.__print_status()
            elif choice in ('clear', "cls"):
                self.__clear_console()
            elif choice in ('traces', 'routes', 'route', 'trace'):
                self.__list_of_traces()
            elif choice in ('tunnels'):
                self.__list_tunnels()
            elif choice in ('tunnels_info'):
                self.__list_tunnels_with_data()
            elif 'create_tunnel' in choice:
                x = choice.split()
                if len(x) != 2:
                    print("Command not found, type 'help' for options\n")
                elif not self.__validate_ip(x[1]):
                    print("Second parameter must be valid IP address\n")
                else:
                    self.__create_tunnel(x[1])
            elif 'ping' in  choice:
                # implement ping
                pass
            else:
                print("Command not found, type 'help' for options\n")

    def __validate_ip(self, s):
        a = s.split('.')
        if len(a) != 4:
            return False
        for x in a:
            if not x.isdigit():
                return False
            i = int(x)
            if i < 0 or i > 255:
                return False
        return True

    def stop_router(self):
        print("Router is turning off")
        self.__ike.kill()
        self.__speaker_process.kill()
        self.__listener_process.kill()
        exit()

    def start(self):
        try:
            while True:
                self.__program_loop()                
                # self.__listen_loop_operation()
        except KeyboardInterrupt:
            self.stop_router()

    def test(self, sck: Socket, message: bytes, delay: int = 5):
        try:
            while True:
                time.sleep(delay)
                self.send(Socket('0.0.0.0', 00000), sck, message)
        except KeyboardInterrupt:
            self.stop_router()
