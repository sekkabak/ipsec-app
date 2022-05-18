import errno
import fcntl
import multiprocessing
import os
import pickle
from select import select
import socket
import sys
import time
from multiprocessing import Process, Manager, Queue
from typing import Union, Optional

from scapy.compat import raw
from scapy.layers.inet import IP, TCP
from scapy.layers.ipsec import SecurityAssociation, ESP
from scapy.packet import Raw
import Router

from StaticRouteRecord import StaticRouteRecord
from Socket import Socket
from Tunnel import Tunnel
from DiffieHellman import DiffieHellman, to_bytes

import logging
logger = logging.getLogger("ike")
# logger.setLevel(logging.DEBUG)

class IKE:
    __ike_port: int = 500
    __interface: str

    __ike_queue_recv: "Queue[bytes]"
    __ike_queue_send: "Queue[tuple[Socket, bytes]]"

    __ike_process: Process
    __router: Router
    
    __sessions: dict

    def __init__(self, interface: str, router: Router):
        self.__interface = interface
        self.__router = router
        
        self.__sessions = multiprocessing.Manager().dict()
        self.__ike_queue_recv = Queue()
        self.__ike_queue_send = Queue()
        self.__start_ike()

    def __start_ike(self):
        self.__ike_process = Process(target=self.__ike_function,
                                          args=(
                                              self.__interface, 
                                              self.__ike_port, 
                                              self.__ike_queue_recv,
                                              self.__ike_queue_send,
                                              self.__sessions))
        self.__ike_process.start()

    @staticmethod
    def __ike_function(interface: str, listen_port: int, recv_qq: "Queue[bytes]", send_qq: "Queue[bytes]", sessions: dict):
        logger.info(f"Initializing IKE")
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_socket.bind((interface, listen_port))
        fcntl.fcntl(server_socket, fcntl.F_SETFL, os.O_NONBLOCK)
        while True:
            try:
                message, address = server_socket.recvfrom(1024)
                sess = sessions.get(address[0])
                if sess != None:
                    if sess[0] == 1:
                        # diffiehellman fase
                        dh = DiffieHellman()
                        ike_socket = Socket(address[0], 500)
                        send_qq.put((ike_socket, dh.public_key))
                        logger.info(f"Sended DH public key to {address[0]}")
                        other_key = int.from_bytes(message, "big")  
                        shared_key = dh.derivate(other_key=other_key)
                        logger.info(f"IKE estabilished DH tunnel with {address[0]}")
                        sessions[address[0]] = [2, shared_key]
                    elif sess[0] == 2 and message == b'IPsec IKE':
                        # IKE fase
                        sess[0] = 3
                        sessions[address[0]] = sess
                    elif sess[0] == 3:
                        # IKE fase
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

                        pass
                else:
                    if message == b'DH init':
                        sessions[address[0]] = [1,]
                    else:
                        recv_qq.put(message)
                logger.info(f"Message to IKE came from {address}")
            except socket.error as e:
                err = e.args[0]
                if err == errno.EAGAIN or err == errno.EWOULDBLOCK:
                    # no data
                    pass
                else:
                    # a "real" error occurred
                    logger.error(e)
                    logger.error("IKE process exiting!")
                    sys.exit(1)
            else:
                recv_qq.put(message)
            if not send_qq.empty():
                address, data = send_qq.get()
                logger.info(f"sending {address} {data}")
                server_socket.sendto(data, address.totuple())
                
    def kill(self):
        self.__ike_process.kill()
    
    def negotiate_keys(self, socket: Socket) -> tuple[int, str, bytes]:
        dh = DiffieHellman()
        ike_socket = Socket(socket.ip, 500)
        self.__ike_queue_send.put((ike_socket, "DH init".encode("utf-8")))
        self.__ike_queue_send.put((ike_socket, dh.public_key))
        logger.info(f"Sended DH public key to {socket.ip}")
        other_key_bytes = self.__ike_queue_recv.get()
        other_key = int.from_bytes(other_key_bytes, "big")  
        shared_key = dh.derivate(other_key=other_key)
        logger.info(f"IKE estabilished DH tunnel with {socket.ip}")
        return 1, "test", "test".encode("utf-8")
