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
from scapy.layers.inet import IP, TCP
from scapy.layers.ipsec import SecurityAssociation, ESP
from scapy.packet import Raw

from StaticRouteRecord import StaticRouteRecord
from Socket import Socket
from Tunnel import Tunnel


# TODO implement IKE
# TODO szatkowanie pakietów w tym miejscu żeby bardziej przypominało to IPsec
class Host:
    __interface: str
    __listen_port: int
    __network_gateway: Socket

    __manager: Manager
    __listener_queue: "Queue[bytes]"
    __listener_process: Process

    def __init__(self, interface: str, listen_port: int, network_gateway: Socket):
        self.__interface = interface
        self.__listen_port = listen_port
        self.__network_gateway = network_gateway

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
        p /= Raw(pickle.dumps(obj))

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
        # self.__listener_process = Process(target=self.sender_process,
        #                                   args=(param,))
        # self.__listener_process.start()
        self.sender_process(param)

    def __listen_loop_operation(self):
        if not self.__listener_queue.empty():
            message = self.__listener_queue.get()
            print(str(message))

    def start(self):
        try:
            while True:
                self.__listen_loop_operation()
        except KeyboardInterrupt:
            self.__listener_process.kill()
