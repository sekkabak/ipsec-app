import errno
import fcntl
import os
import pickle
from pyexpat.errors import messages
import socket
import sys
import threading
import time
from multiprocessing import Process, Manager, Queue
from typing import Union, Optional

from scapy.compat import raw
from scapy.layers.inet import IP, TCP
from scapy.layers.ipsec import SecurityAssociation, ESP
from scapy.packet import Raw

from IKE import IKEService
# import IKE

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

    __ike: IKEService.IKEService

    def __init__(self, interface: str, listen_port: int, speaker_port: int):
        self.__interface = interface
        self.__listen_port = listen_port
        self.__speaker_port = speaker_port
        self.__static_routes_table = []
        self.__tunnels = []

        self.__ike = IKEService.IKEService(interface, self.__tunnels)

        self.__listener_queue = Queue()
        self.__speaker_queue = Queue()

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

    def __get_trace(self, dest_ip: str) -> Socket:
        static_route = next(
            static_route for static_route in self.__static_routes_table if static_route.network_ip == dest_ip)
        return static_route.reach_socket

    # TODO implementation dla UDP
    def __encrypt_package_TCP(self, sender: Socket, destination: Socket, message: bytes, tunnel: Tunnel) -> bytes:
        sa = SecurityAssociation(ESP, spi=tunnel.spi, crypt_algo=tunnel.crypt_algo, crypt_key=tunnel.crypt_key)
        p = IP(src=sender.ip, dst=destination.ip)
        p /= TCP(sport=sender.port, dport=destination.port)
        p /= Raw(pickle.dumps(message))

        e = IP(src=self.__interface, dst=tunnel.dst_ip)
        e /= Raw(sa.encrypt(p))
        return raw(e)
    
    def __encrypt_package_UDP(self, sender: Socket, destination: Socket, message: bytes, tunnel: Tunnel) -> bytes:
        sa = SecurityAssociation(ESP, spi=tunnel.spi, crypt_algo=tunnel.crypt_algo, crypt_key=tunnel.crypt_key)
        p = IP(src=sender.ip, dst=destination.ip)
        p /= TCP(sport=sender.port, dport=destination.port)
        p /= Raw(pickle.dumps(message))

        e = IP(src=self.__interface, dst=tunnel.dst_ip)
        e /= Raw(sa.encrypt(p))
        return raw(e)

    def __decrypt_packet(self, packet: bytes, tunnel: Tunnel):
        sa = SecurityAssociation(ESP, spi=tunnel.spi, crypt_algo=tunnel.crypt_algo, crypt_key=tunnel.crypt_key)
        return sa.decrypt(IP(packet))

    def receive_estabilished_tunnel(self, tunnel: Tunnel):
        self.__tunnels.append(tunnel)

    def __has_tunnel(self, socket: Socket) -> Optional[Tunnel]:
        try:
            for tunnel in self.__tunnels:
                if tunnel.dst_ip == socket.ip:
                    return tunnel
            return None
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

        network_dst = self.find_network(packet.dst)
        tunnel = self.__has_tunnel(network_dst.dst)
        if tunnel != None:
            import traceback
            try:
                sender = self.find_network(packet.src)
                destination = Socket(packet.dst, packet.dport)
                logger.error(f"Packet was encrypted from {sender.totuple()} to {destination.totuple()}")
                package = self.__encrypt_package_TCP(sender, destination, packet.payload.load, tunnel)
                trace = self.__get_trace(tunnel.network_ip)
                self.__speaker_queue.put((trace, package))
            except Exception as e:
                logger.error(f"{traceback.print_exc()}")
                logger.error(f"{e}")

    def __handle_network_inbound_UDP_traffic(self, message: bytes):
        packet = IP(message)
        
        network_dst = self.find_network(packet.dst)
        tunnel = self.__has_tunnel(network_dst.dst)
        if tunnel != None:
            import traceback
            try:
                sender = self.find_network(packet.src)
                destination = Socket(packet.dst, packet.dport)
                logger.error(f"Packet was encrypted from {sender.totuple()} to {destination.totuple()}")
                package = self.__encrypt_package_UDP(sender, destination, packet.payload.load, tunnel)
                trace = self.__get_trace(tunnel.network_ip)
                self.__speaker_queue.put((trace, package))
            except Exception as e:
                logger.error(f"{traceback.print_exc()}")
                logger.error(f"{e}")
            
    def __handle_network_outbound_traffic(self, message: bytes):
        packet = IP(message)
        
        network_dst = self.find_network(packet.dst)
        tunnel = self.__has_tunnel(network_dst.dst)
        if tunnel != None:
            import traceback
            try:
                data = self.__decrypt_packet(packet.payload.load, tunnel)
                inner_packet: IP = data
                sckt: Socket = Socket(inner_packet.dst, inner_packet.dport)
                logger.error(f"Packet was send to {sckt.totuple()}")
                self.__speaker_queue.put((sckt, raw(data)))
            except Exception as e:
                logger.error(f"{traceback.print_exc()}")
                logger.error(f"{e}")
                
    def __listen_loop_operation(self):
        while True:
            if not self.__listener_queue.empty():
                message = self.__listener_queue.get()
                try:
                    packet = IP(message)
                    layers = self.__scapy_get_layers(packet)
                    layers_names = [x.name for x in layers]
                    logger.info(f"{layers_names}")
                    
                    if packet.dst == self.__interface and layers_names == ['IP', 'Raw']:
                        logger.info(f"Outbound packet came")
                        self.__handle_network_outbound_traffic(message)
                    elif layers_names == ['IP', 'TCP', 'Raw']:
                        logger.info(f"Inbound TCP packet came")
                        self.__handle_network_inbound_TCP_traffic(message)
                    elif layers_names == ['IP', 'UDP', 'Raw']:
                        logger.info(f"Inbound UDP packet came")
                        self.__handle_network_inbound_UDP_traffic(message)
                        
                except:
                    pass
    
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
        result1 = self.__ike.estabilish_DH_channel(s.ip)
        if result1:
            result2 = self.__ike.propose_IPsec_keys(s.ip)
        
    def __program_loop(self):
        try:
            while True:
                print("Welcome in Router emulator shell")
                print("type help for options")
                
                while True:
                    choice = ""
                    choice = input("$ ")
                    if choice in (''):
                        pass
                    elif choice in ('exit', 'quit'):
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
        except KeyboardInterrupt:
            self.stop_router()
        
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
        self.__speaker_process.kill()
        self.__listener_process.kill()
        exit()

    def start(self):
        self.__start_listener()
        self.__start_speaker()
        
        t_listen_loop_operation = threading.Thread(target=self.__listen_loop_operation, daemon=True)
        t_listen_loop_operation.start()
   
        self.__program_loop()

    def test(self, sck: Socket, message: bytes, delay: int = 5):
        try:
            while True:
                time.sleep(delay)
                self.send(Socket('0.0.0.0', 00000), sck, message)
        except KeyboardInterrupt:
            self.stop_router()
