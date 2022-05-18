import errno
import fcntl
import os
import pickle
from pyexpat.errors import messages
import socket
import sys
import time
from multiprocessing import Process, Manager, Queue
from typing import Union, Optional

from scapy.compat import raw
from scapy.layers.inet import IP, TCP
from scapy.layers.ipsec import SecurityAssociation, ESP
from scapy.packet import Raw

from IKE_old import IKE
# import IKE

from StaticRouteRecord import StaticRouteRecord
from Socket import Socket
from Tunnel import Tunnel
from DiffieHellman import DiffieHellman

import asyncio

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
                # logger.error(f"{data} {address.totuple()}")
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

    # def send(self, sender: Socket, dst_host: Socket, message: bytes):
    #     tunnel = self.__has_tunnel(dst_host)
    #     # TODO not this way, it only supports 2 routers
    #     if not tunnel:
    #         tunnel = self.__try_to_setup_tunnel(dst_host)
    #     package = self.__encrypt_package(sender, message, tunnel)
    #     trace = self.__get_trace(tunnel.network_ip)
    #     self.__speaker_queue.put((trace.totuple(), package))

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

    # def __try_to_setup_tunnel(self, dst_host: Socket) -> Tunnel:
    #     tunnel = Tunnel()
    #     network = self.find_network(dst_host.ip)
    #     if not network:
    #         raise Exception("Cannot reach that network")
    #     tunnel.network_ip = network.ip
    #     tunnel.network_port = network.port
    #     tunnel.dst_ip = dst_host.ip
    #     tunnel.dst_port = dst_host.port

    #     # TODO add Diffie-Hellman
    #     tunnel.crypt_algo = 'AES-CBC'
    #     tunnel.spi = 0xdeadbeef
    #     tunnel.crypt_key = b'aaaaaaaaaaaaaaaa'

    #     return tunnel

    def __has_tunnel(self, spi: Socket) -> Optional[Tunnel]:
        try:
            for tunnel in self.__tunnels:
                if tunnel.spi == spi:
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
        
        # TODO debug
        tunnel = Tunnel()
        tunnel.crypt_algo = 'AES-CBC'
        tunnel.spi = 0xdeadbeef
        tunnel.crypt_key = b'aaaaaaaaaaaaaaaa'
        tunnel.dst_ip = '127.0.0.13'
        tunnel.dst_port = 10000
        tunnel.network_ip = '127.0.0.13'
        tunnel.network_port = 10000
        self.__tunnels.append(tunnel)
        
        tunnel = self.__has_tunnel(0xdeadbeef)
        if not tunnel:
            logger.warning(f"no tunnel")
            # unknown source
            # ignore
            pass
        else:
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
        
        # TODO debug
        tunnel = Tunnel()
        tunnel.crypt_algo = 'AES-CBC'
        tunnel.spi = 0xdeadbeef
        tunnel.crypt_key = b'aaaaaaaaaaaaaaaa'
        tunnel.dst_ip = '127.0.0.13'
        tunnel.dst_port = 10000
        tunnel.network_ip = '127.0.0.13'
        tunnel.network_port = 10000
        self.__tunnels.append(tunnel)
        
        tunnel = self.__has_tunnel(0xdeadbeef)
        if not tunnel:
            logger.warning(f"no tunnel")
            # unknown source
            # ignore
            pass
        else:
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
        
        # TODO debug
        tunnel = Tunnel()
        
        tunnel.crypt_algo = 'AES-CBC'
        tunnel.spi = 0xdeadbeef
        tunnel.crypt_key = b'aaaaaaaaaaaaaaaa'
        
        tunnel.dst_ip = '127.0.0.13'
        tunnel.dst_port = 10000
        tunnel.network_ip = '127.0.0.13'
        tunnel.network_port = 10000
        self.__tunnels.append(tunnel)
        
        tunnel = self.__has_tunnel(0xdeadbeef)
        if not tunnel:
            logger.info(f"no tunnel")
            # unknown source
            # ignore
            pass
        else:
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
            
    def do_stuff_periodically(self, interval, periodic_function):
        while True:
            # print("timer start")
            # logger.error(f"test before loop")
            # asyncio.sleep(interval)
            periodic_function()
    
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
        
    async def __program_loop(self, loop):
        try:
            while True:
                # logger.error(f"test")
                # loop.create_task(greet_every_two_seconds())
                
                # asyncio.create_task(self.do_stuff_periodically(1, self.__listen_loop_operation))
                # asyncio.ensure_future()
                # loop.call_soon_threadsafe(asyncio.async, g())
                # asyncio.create_task()
                
                self.__print_status()
                # self.do_stuff_periodically(1, self.__listen_loop_operation)
                
                
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
        self.__ike.kill()
        self.__speaker_process.kill()
        self.__listener_process.kill()
        exit()

    def start(self):
        loop = asyncio.get_event_loop()
        loop.run_until_complete(self.__program_loop(loop))
        loop.close()

    def test(self, sck: Socket, message: bytes, delay: int = 5):
        try:
            while True:
                time.sleep(delay)
                self.send(Socket('0.0.0.0', 00000), sck, message)
        except KeyboardInterrupt:
            self.stop_router()
