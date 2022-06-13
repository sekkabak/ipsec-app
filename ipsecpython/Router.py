import os
import pickle
import socket
import threading
import time
from multiprocessing import Process, Queue
from typing import Optional

from scapy.compat import raw
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.ipsec import SecurityAssociation, ESP
from scapy.packet import Raw
from scapy.all import send, conf, L3RawSocket
from IKE import IKEService

from StaticRouteRecord import StaticRouteRecord
from Socket import Socket
from Tunnel import Tunnel
import readline


import logging
logger = logging.getLogger("router")
logger.setLevel(logging.DEBUG)

conf.L3socket=L3RawSocket

class Router:
    __interface: str
    __listen_port: int
    __speaker_port: int
    __static_routes_table: list[StaticRouteRecord]
    __tunnels: list[Tunnel]

    __listener_queue: "Queue[bytes]"
    __speaker_queue: "Queue[tuple[Socket, bytes]]"

    __listener_process: Process
    __speaker_process: Process

    __ike: IKEService.IKEService

    # TODO implement map
    __ping_response: bool = False

    def __init__(self, interface: str, listen_port: int, speaker_port: int):
        self.__interface = interface
        self.__listen_port = listen_port
        self.__speaker_port = speaker_port
        self.__static_routes_table = []
        self.__tunnels = []

        self.__ike = IKEService.IKEService(interface, self.__tunnels, self.find_network)

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
            time.sleep(0.05)
            message, address = server_socket.recvfrom(1024)
            qq.put(message)
            time.sleep(0.05)

    def __start_speaker(self):
        self.__speaker_process = Process(target=self.__speaker_function,
                                         args=(self.__interface, self.__speaker_port, self.__speaker_queue))
        self.__speaker_process.start()

    @staticmethod
    def __speaker_function(interface: str, speaker_port: int, qq: "Queue[tuple[Socket, bytes]]"):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_socket.bind((interface, speaker_port))
        while True:
            time.sleep(0.05)
            if not qq.empty():
                address, data = qq.get()
                server_socket.sendto(data, address.totuple())
            time.sleep(0.05)

    def send_TCP_packet(self, ip: str, data: bytes):
        # TODO implementacja sprawdzania czy wysylamy na endpoint ze zestawionym ipsecem

        dest_ip, port, is_hopping = self.find_network(ip)
        internet_packet = IP()
        internet_packet.src = self.__interface
        internet_packet.dst = ip
        tcp_packet = TCP()
        raw_data = data
        self.__speaker_queue.put((Socket(dest_ip, port), raw(internet_packet/tcp_packet/raw_data)))

    def send_ICMP_packet(self, ip: str, data: bytes):
        dest_ip, port, is_hopping = self.find_network(ip)
        internet_packet = IP(src=self.__interface, dst=ip, ttl=20)
        icmp_packet = ICMP()
        raw_data = data
        logger.info(f"{dest_ip, port}, {raw(internet_packet/icmp_packet/raw_data)}")
        self.__speaker_queue.put((Socket(dest_ip, port), raw(internet_packet/icmp_packet/raw_data)))

    @staticmethod
    def __get_network_address(ip: str, mask: str) -> str:
        """Returns network address using mask calculation

        Returns:
            str: Network address of given ip
        """
        return ".".join(map(str, [i & m for i, m in zip(map(int, ip.split(".")),
                                                        map(int, mask.split(".")))]))

    def find_network(self, dest_ip: str):
        """Returns way to move to given @dest_ip target

        Raises:
            IndexError: When route cannot be found

        Returns:
            tuple[str, bool]: [next send ip, port, if hopping]
        """
        for ip, mask, next_hop, port in self.__static_routes_table:

            # no jumping directly send data
            if ip == dest_ip and next_hop == False:
                return (dest_ip, port, False)

            output = Router.__get_network_address(dest_ip, mask)

            # jump to connected router
            if output == ip and next_hop == None:
                return (ip, port, True)
            
            # jump through networks
            elif next_hop != None:
                return (next_hop, port, True)
        raise IndexError("Cannot find network")

    def add_to_static_routes(self, ip: str, mask: str, next_hop: str = None, port: int = 10000):
        """
        Adds static route to this router

        If next_hop is None then given host is directly connected to this router

        Args:
            ip (str): Ip address
            mask (str): mast for network in x.x.x.x template
            next_hop (str, optional): Next device to reach target. Defaults to None.
            port (int): Port needed to send packet. 10000 by default
        """
        self.__static_routes_table.append(StaticRouteRecord(ip, mask, next_hop, port))

    # def __get_trace(self, dest_ip: str) -> Socket:
    #     try:
    #         static_route = next(static_route for static_route in self.__static_routes_table if static_route.network_ip == dest_ip)
    #         return static_route.reach_socket
    #     except StopIteration:
    #         return None

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
                # trace_ip = self.find_network(tunnel.network_ip)
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
    
    def __handle_ping(self, message: bytes):
        packet = IP(message)
        raw_data = raw(packet[Raw])
        if raw_data == b'ping':
            logger.info(f"Sending pong packet to {packet.src}")
            self.send_ICMP_packet(packet.src, b'pong')
        elif raw_data == b'pong':
            self.__ping_response = True
        
    def __listen_loop_operation(self):
        while True:
            time.sleep(0.05)
            if not self.__listener_queue.empty():
                message = self.__listener_queue.get()
                try:
                    packet = IP(message)
                    layers = self.__scapy_get_layers(packet)
                    layers_names = [x.name for x in layers]
                    logger.info(f"Packet came with layers: {layers_names}")

                    if packet.dst != self.__interface:
                        try:
                            next_dst, port, is_hopping = self.find_network(packet.dst)
                            logger.info(f"Forwarding packet from {packet.src} to {next_dst}")

                            if('TCP' in layers_names or 'UDP' in layers_names):
                                packet.dst=next_dst
                                send(packet, verbose=False)
                            else:
                                self.__speaker_queue.put((Socket(next_dst, port), message))
                        except Exception:
                            logger.warning(f"Dead end for packet to {packet.dst}")
                            continue # dead end for packet
                        continue
                    
                    if layers_names == ['IP', 'ICMP', 'Raw']:
                        logger.info(f"Ping packet")
                        self.__handle_ping(message)
                        continue

                    # if layers_names == ['IP', 'UDP', 'Raw']:
                    #     logger.info(f"UDP packet came")
                    #     self.__handle_network_inbound_UDP_traffic(message)
                    #     continue

                    # if layers_names == ['IP', 'TCP', 'Raw']:
                    #     logger.info(f"Inbound TCP packet came")
                    #     self.__handle_network_inbound_TCP_traffic(message)
                    #     continue

                    # if layers_names == ['IP', 'Raw']:
                    #     logger.info(f"Outbound packet came")
                    #     self.__handle_network_outbound_traffic(message)
                    #     continue
                        
                except:
                    pass
            time.sleep(0.05)

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
            print(f"\tKey: {tunnel.crypt_key}")
            print(f"\tAlgorithm: {tunnel.crypt_algo}")
            i+=1
        print("")
    
    def __create_tunnel(self, ip):
        network_ip, port, is_hopping = self.find_network(ip)
        result1 = self.__ike.estabilish_DH_channel(ip, network_ip, port, is_hopping)
        if result1:
            result2 = self.__ike.propose_IPsec_keys(ip, network_ip, port, is_hopping)

    def __ping(self, ip, timeout=5):
        try:
            self.find_network(ip)
            self.__ping_response = False
            self.send_ICMP_packet(ip, "ping")
            i=0
            while i<timeout and self.__ping_response == False:
                time.sleep(0.001)
                i+=0.001
            if self.__ping_response == True:
                delay="{:.3f}".format(i)
                print(f"Host responded in {delay}s")
            else:
                print(f"Timeout")
        except IndexError:
            print("Destination host unreachable")
        
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
                        elif not Router.__validate_ip(x[1]):
                            print("Second parameter must be valid IP address\n")
                        else:
                            self.__create_tunnel(x[1])
                    elif 'ping' in choice:
                        x = choice.split()
                        if len(x) != 2:
                            print("Command not found, type 'help' for options\n")
                        elif not Router.__validate_ip(x[1]):
                            print("Second parameter must be valid IP address\n")
                        else:
                            self.__ping(x[1])
                    else:
                        print("Command not found, type 'help' for options\n")
        except KeyboardInterrupt:
            self.stop_router()
    
    @staticmethod
    def __validate_ip(s):
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
