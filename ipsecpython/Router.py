import os
import sys
import pickle
import socket
import threading
import time
import sys
import errno
import http.server
import socketserver
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
from loguru import logger
from httpserv import MyServer


file_log_path = 'logs/' + os.path.splitext(sys.argv[0])[0].split("/")[-1] + ".log"
logger.remove()
logger.add(sink=file_log_path, enqueue=True, backtrace=True, diagnose=True, level="INFO")
conf.L3socket=L3RawSocket

class Router:
    __interface: str
    __listen_port: int
    __speaker_port: int
    __static_routes_table: list
    __tunnels: list

    __listener_queue: "Queue[bytes]"
    __speaker_queue: "Queue[tuple[Socket, bytes]]"

    __listener_process: Process
    __speaker_process: Process

    __ike: IKEService.IKEService

    # TODO implement map
    __ping_response: bool = False

    def __init__(self, interface: str, listen_port: int, speaker_port: int):
        self.__check_sudo_permissions()

        self.__interface = interface
        self.__listen_port = listen_port
        self.__speaker_port = speaker_port
        self.__static_routes_table = []
        self.__tunnels = []

        logger.info(f"Initializing Router")
        logger.info(f"IP: {self.__interface}")
        logger.info(f"IKE port: 500")
        logger.info(f"listener port: {self.__listen_port}")
        logger.info(f"sender port: {self.__speaker_port}")
        logger.info(f"")


        threading.Thread(target=self.run_logs_http, daemon=True).start()

        self.__ike = IKEService.IKEService(interface, self.__tunnels, self.find_network)

        self.__listener_queue = Queue()
        self.__speaker_queue = Queue()

    def run_logs_http(self):
        Handler = MyServer
        Handler.file = file_log_path
        with socketserver.TCPServer((self.__interface, 10500), Handler) as httpd:
            httpd.serve_forever()

    def __check_sudo_permissions(self):
        if os.geteuid() != 0:
            sys.exit("Routers can only run under Unix and you need root permissions")

    def __start_listener(self):
        self.__listener_process = Process(target=self.__listener_function,
                                          args=(self.__interface, self.__listen_port, self.__listener_queue,))
        self.__listener_process.start()

    @staticmethod
    @logger.catch
    def __listener_function(interface: str, listen_port: int, qq: "Queue[bytes]"):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_socket.bind((interface, listen_port))

        while True:
            time.sleep(0.05)
            message, address = server_socket.recvfrom(33000)

            qq.put(message)
            time.sleep(0.05)

    @logger.catch
    def __start_speaker(self):
        self.__speaker_process = Process(target=self.__speaker_function,
                                         args=(self.__interface, self.__speaker_port, self.__speaker_queue))
        self.__speaker_process.start()

    @staticmethod
    @logger.catch
    def __speaker_function(interface: str, speaker_port: int, qq: "Queue[tuple[Socket, bytes]]"):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_socket.bind((interface, speaker_port))
        while True:
            time.sleep(0.05)
            if not qq.empty():
                address, data = qq.get()
                server_socket.sendto(data, address.totuple())
            time.sleep(0.05)

    @logger.catch
    def send_TCP_packet(self, ip: str, data: bytes):
        dest_ip, port, is_hopping = self.find_network(ip)
        internet_packet = IP()
        internet_packet.src = self.__interface
        internet_packet.dst = ip
        tcp_packet = TCP()
        raw_data = data
        self.__speaker_queue.put((Socket(dest_ip, port), raw(internet_packet/tcp_packet/raw_data)))

    @logger.catch
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

    def get_network_ip(self, dest_ip: str):
        for ip, mask, next_hop, port in self.__static_routes_table:
            output = Router.__get_network_address(dest_ip, mask)
            if output == ip:
                return (ip, port)
        return None

    @logger.catch
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

    @logger.catch
    def __encrypt_package_TCP(self, sender: Socket, destination: Socket, message: bytes, tunnel: Tunnel) -> bytes:
        sa = SecurityAssociation(ESP, spi=tunnel.spi, crypt_algo=tunnel.crypt_algo, crypt_key=tunnel.crypt_key)
        p = IP(src=sender.ip, dst=destination.ip)
        p /= TCP(sport=sender.port, dport=destination.port)
        p /= Raw(message)

        e = IP(src=self.__interface, dst=tunnel.dst_ip)
        e /= Raw(sa.encrypt(p))
        return raw(e)
    
    @logger.catch
    def __encrypt_package_UDP(self, sender: Socket, destination: Socket, message: bytes, tunnel: Tunnel) -> bytes:
        sa = SecurityAssociation(ESP, spi=tunnel.spi, crypt_algo=tunnel.crypt_algo, crypt_key=tunnel.crypt_key)
        p = IP(src=sender.ip, dst=destination.ip)
        p /= TCP(sport=sender.port, dport=destination.port)
        p /= Raw(message)

        e = IP(src=self.__interface, dst=tunnel.dst_ip)
        e /= Raw(sa.encrypt(p))
        return raw(e)

    @logger.catch
    def __decrypt_packet(self, packet: bytes, tunnel: Tunnel):
        sa = SecurityAssociation(ESP, spi=tunnel.spi, crypt_algo=tunnel.crypt_algo, crypt_key=tunnel.crypt_key)
        packet = sa.decrypt(IP(packet))
        logger.info("")
        logger.info(f"Decrypting ESP packet")
        logger.info(f"Content of packet after decrypt: {bytes(packet)[:300]}")
        logger.info("")
        return packet

    def receive_estabilished_tunnel(self, tunnel: Tunnel):
        self.__tunnels.append(tunnel)

    def __has_tunnel(self, ip) -> Optional[Tunnel]:
        try:
            for tunnel in self.__tunnels:
                if tunnel.dst_ip == ip:
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

    @logger.catch
    def __handle_ping(self, message: bytes):
        packet = IP(message)
        raw_data = raw(packet[Raw])
        if raw_data == b'ping':
            logger.info(f"Sending pong packet to {packet.src}")
            self.send_ICMP_packet(packet.src, b'pong')
        elif raw_data == b'pong':
            self.__ping_response = True
        
    @logger.catch
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

                    network = self.get_network_ip(packet.dst)
                    # network = self.find_network(packet.dst)
                    if network != None:
                        next_dst = network[0]
                        port = network[1]
                        tunnel = self.__has_tunnel(next_dst)
                    else:
                        next_dst = "0"
                        port = 0
                        tunnel = None

                    if packet.dst != self.__interface and tunnel != None and ('TCP' in layers_names or 'UDP' in layers_names):
                        logger.info(f"Packet that can be tunneled from {packet.dst} in {tunnel.dst_ip}")
                        if 'TCP' in layers_names:
                            data = self.__encrypt_package_TCP(Socket(packet.src, packet.sport), Socket(packet.dst, packet.dport), raw(packet[Raw]), tunnel)
                        elif 'UDP' in layers_names:
                            data = self.__encrypt_package_UDP(Socket(packet.src, packet.sport), Socket(packet.dst, packet.dport), raw(packet[Raw]), tunnel)
                        self.__speaker_queue.put((Socket(tunnel.network_ip, tunnel.network_port), data))
                    elif packet.dst != self.__interface:
                        try:
                            next_dst, port, is_hopping = self.find_network(packet.dst)
                            logger.info("")
                            logger.info(f"Forwarding packet from {packet.src} to {next_dst}")
                            logger.info(f"Content of packet: {bytes(packet)[:300]}")
                            logger.info("")

                            if 'ISAKMP' in layers_names:
                                packet.dst = next_dst
                                send(packet, verbose=False)
                            else:
                                self.__speaker_queue.put((Socket(next_dst, port), message))
                        except Exception:
                            logger.warning(f"Dead end for packet to {packet.dst}")
                            continue # dead end for packet
                        continue
                    
                    if layers_names == ['IP', 'ICMP', 'Raw']:
                        logger.info("")
                        logger.info(f"Ping packet")
                        logger.info(f"Content of packet: {bytes(packet)[:300]}")
                        logger.info("")
                        self.__handle_ping(message)
                        continue
                    elif layers_names == ['IP', 'Raw']:
                        tunnel = self.__has_tunnel(packet.src)
                        decrypted_packet = self.__decrypt_packet(raw(packet[Raw]), tunnel)

                        next_dst, port, is_hopping = self.find_network(decrypted_packet.dst)
                        self.__speaker_queue.put((Socket(next_dst, port), raw(decrypted_packet)))
                except:
                    import traceback
                    print(traceback.format_exc())
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
    
    @logger.catch
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
