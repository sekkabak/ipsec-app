import threading
from scapy.compat import raw
from scapy.layers.inet import IP, TCP
from scapy.layers.ipsec import SecurityAssociation, ESP
from scapy.packet import Raw
from multiprocessing import Process
import pickle
import socket
from Socket import Socket

import pickle
import socket
import time
from multiprocessing import Process, Manager, Queue
from typing import Union, Optional

from scapy.compat import raw
from scapy.layers.inet import IP, TCP, ICMP
from scapy.layers.ipsec import SecurityAssociation, ESP
from scapy.packet import Raw
from scapy.all import send

from StaticRouteRecord import StaticRouteRecord
from Socket import Socket
from Tunnel import Tunnel

import logging
logger = logging.getLogger("router")
logger.setLevel(logging.DEBUG)


class Host:
    __interface: str
    __listen_port: int
    __network_gateway: Socket

    __ping_response: bool = False
    t_listener: threading.Thread

    def __init__(self, interface: str, listen_port: int, network_gateway: Socket):
        self.__interface = interface
        self.__listen_port = listen_port
        self.__network_gateway = network_gateway

        self.t_listener = threading.Thread(target=self.__listener, daemon=True)
        self.t_listener.start()

    def __listener(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_socket.bind((self.__interface, self.__listen_port))

        while True:
            message, address = server_socket.recvfrom(1024)

            packet = IP(message)
            layers = self.__scapy_get_layers(packet)
            layers_names = [x.name for x in layers]
            logger.info(f"Packet came with layers: {layers_names}")
            
            if layers_names == ['IP', 'ICMP', 'Raw']:
                raw_data = raw(packet[Raw])
                if raw_data == b'ping':
                    logger.info(f"Sending pong packet to {packet.src}")
                    self.send_ICMP_packet(packet.src, b'pong')
                elif raw_data == b'pong':
                    self.__ping_response = True
                continue

            data = pickle.loads(packet[Raw].load)
            logger.error(f"From {packet.src} came data: {data}")

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

    @staticmethod
    def sender_process(data):
        """This method runs in thread"""
        obj, dst_ip, dst_port, src_ip, src_port, network_gateway_ip, network_gateway_port = data

        # socket initialization
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind((src_ip, 0))

        # creating encapsulated packet
        p = IP(src=src_ip, dst=dst_ip)
        p /= TCP(sport=src_port, dport=dst_port)
        p /= Raw(obj.encode("utf-8"))
        # p /= Raw(pickle.dumps(obj))

        # sending encapsulated packet
        s.sendto(raw(p), (network_gateway_ip, network_gateway_port))
        s.close()

    def send(self, data: any, dst: str, dst_port: int):
        param = (data,
                 dst,
                 dst_port,
                 self.__interface,
                 self.__listen_port,
                 self.__network_gateway.ip,
                 self.__network_gateway.port)
        self.sender_process(param)

    def send_ICMP_packet(self, ip: str, data: bytes):
        internet_packet = IP(src=self.__interface, dst=ip)
        icmp_packet = ICMP()
        raw_data = data

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind((self.__interface, 0))
        s.sendto(raw(internet_packet/icmp_packet/raw_data), (self.__network_gateway.ip, self.__network_gateway.port))
        s.close()
    
    def ping(self, ip, timeout=5):
        try:
            self.__ping_response = False
            self.send_ICMP_packet(ip, b'ping')

            i=0
            while i<timeout and self.__ping_response == False:
                time.sleep(0.001)
                i+=0.001
            if self.__ping_response == True:
                delay="{:.3f}".format(i)
                return f"Host responded in {delay}s"
            else:
                return "Timeout"
        except IndexError:
            return "Destination host unreachable"

    def listen_forever(self):
        self.t_listener.join()
