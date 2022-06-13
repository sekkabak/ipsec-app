from __future__ import annotations
from audioop import add

import errno
import fcntl
import os
import pickle
import socket
import threading
import time
import random

from scapy.compat import raw
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.ipsec import SecurityAssociation, ESP
from scapy.packet import Raw

from Socket import Socket
from Tunnel import Tunnel
from DiffieHellman import DiffieHellman, to_bytes

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import sys

import logging
logger = logging.getLogger("ike")
logger.setLevel(logging.DEBUG)


class IKEService:
    __ike_port: int = 500
    __interface: str
    __tunnels: list
    __server_socket: socket.socket
    __sessions: dict
    __dh: DiffieHellman
    __find_network_f: function
    t_listener: threading.Thread
    
    def __init__(self, interface: str, tunnels: list, find_network: function) -> None:
        logger.info(f"Initializing IKE")
        self.__interface = interface
        self.__tunnels = tunnels
        self.__sessions = dict()
        self.__find_network_f = find_network
        
        self.__dh = DiffieHellman()

        self.__server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.__server_socket.bind((self.__interface, self.__ike_port))
        fcntl.fcntl(self.__server_socket, fcntl.F_SETFL, os.O_NONBLOCK)
        
        self.t_listener = threading.Thread(target=self.__listener, daemon=True)
        self.t_listener.start()
        
    def __listener(self):
        while True:
            try:
                message, address = self.__server_socket.recvfrom(1024)
                sess = self.__sessions.get(address[0])
                logger.info(f"Message to IKE came from {address}")

                original_ip = address[0]
                network_ip, port, is_hopping = self.__find_network_f(original_ip)
                ike_socket = Socket(network_ip, port)
                if message == b'DH init':
                        self.__sessions[original_ip] = [1, None]
                        packet = IP(src=self.__interface, dst=original_ip)
                        packet /= UDP(dport=500, sport=500)
                        packet /= self.__dh.public_key
                        self.__send(ike_socket, raw(packet))
                        logger.info(f"Sended DH public key to {original_ip}")
                elif sess != None:
                    if sess[0] == 1: # diffiehellman fase
                        other_key = int.from_bytes(message, "big")  
                        shared_key = self.__dh.derivate(other_key=other_key)
                        logger.info(f"IKE estabilished DH tunnel with {original_ip}")
                        self.__sessions[original_ip] = [2, shared_key]
                    elif sess[0] == 2 and message == b'IPsec IKE':  # IKE INIT fase
                        sess[0] = 3
                        self.__sessions[original_ip] = sess
                    elif sess[0] == 3: # IKE fase
                        key = self.__sessions[original_ip][1]
                        
                        cipher = Cipher(algorithms.AES(key[:32]), modes.ECB())
                        decryptor = cipher.decryptor()
                        data = decryptor.update(message) + decryptor.finalize()
                        data = data[:-data[-1]]
                        spi, crypt_algo, crypt_key = pickle.loads(data)
                        logger.info(f"spi: {spi}")
                        logger.info(f"crypt_algo: {crypt_algo}")
                        logger.info(f"crypt_key: {crypt_key}")
                        
                        # TODO check if spi is ok
                        packet = IP(src=self.__interface, dst=original_ip)
                        packet /= UDP(dport=500, sport=500)
                        packet /= b'OK'
                        self.__send(ike_socket, raw(packet))
                        tunnel = Tunnel()
                        tunnel.spi = spi
                        tunnel.crypt_algo = crypt_algo
                        tunnel.crypt_key = crypt_key
                        tunnel.dst_ip = original_ip
                        tunnel.network_ip = network_ip
                        tunnel.network_port = port
                        self.__tunnels.append(tunnel)
                        logger.info(f"IPsec tunnel to {original_ip} has been created")

                    elif sess[0] == 4 and message == b'OK': # IKE rcv respond
                        tunnel = Tunnel()
                        tunnel.spi, tunnel.crypt_algo, tunnel.crypt_key = sess[2]
                        tunnel.dst_ip = original_ip
                        tunnel.network_ip = network_ip
                        tunnel.network_port = port
                        self.__tunnels.append(tunnel)
                        logger.info(f"IPsec tunnel to {original_ip} has been created")
            except socket.error as e:
                err = e.args[0]
                if err == errno.EAGAIN or err == errno.EWOULDBLOCK:
                    # no data
                    pass
                else:
                    # a "real" error occurred
                    import traceback
                    traceback.print_exc()
                    logger.error(e)

    def estabilish_DH_channel(self, original_ip: str, network_ip: str, port: int, is_hopping: str, timeout = 5):
        packet = IP(src=self.__interface, dst=original_ip)
        packet /= UDP(dport=500, sport=500)
        packet /= "DH init".encode("utf-8")
        
        ike_socket = Socket(network_ip, port)
        
        self.__send(ike_socket, raw(packet))
        logger.info(f"Sended DH init packet to {original_ip}")

        packet = IP(src=self.__interface, dst=original_ip)
        packet /= UDP(dport=500, sport=500)
        packet /= self.__dh.public_key
        
        self.__send(ike_socket, raw(packet))
        logger.info(f"Sended DH public key to {original_ip}")
        self.__sessions[original_ip] = [1, None]
        
        must_end = time.time() + timeout
        while time.time() < must_end:
            if self.__sessions[original_ip][0] > 1: 
                return True
            time.sleep(0.1)
        
        del self.__sessions[original_ip]
        return False

    def propose_IPsec_keys(self, original_ip: str, network_ip: str, port: int, is_hopping: str, timeout = 5):
        ike_socket = Socket(network_ip, port)
        
        if self.__sessions[original_ip] == None or self.__sessions[original_ip][0] < 2:
            logger.error(f"{self.__sessions[original_ip]}")
            return False
        
        key = self.__sessions[original_ip][1]
        

        packet = IP(src=self.__interface, dst=original_ip)
        packet /= UDP(dport=500, sport=500)
        packet /= "IPsec IKE".encode("utf-8")
        self.__send(ike_socket, raw(packet))
        logger.info(f"Sended IPsec IKE init packet to {network_ip}")

        cipher = Cipher(algorithms.AES(key[:32]), modes.ECB())
        encryptor = cipher.encryptor()
        
        crypt_algo = 'AES-CBC'
        spi = random.randint(0, 4294967295)
        crypt_key = os.urandom(16)
        
        data = pickle.dumps([spi, crypt_algo, crypt_key], 0)
        length = 16 - (len(data) % 16)
        data += bytes([length])*length
        
        ct = encryptor.update(data) + encryptor.finalize()
        
        packet = IP(src=self.__interface, dst=original_ip)
        packet /= UDP(dport=500, sport=500)
        packet /= ct
        self.__send(ike_socket, raw(packet))
        logger.info(f"Sended IPsec IKE keys to {network_ip}")
        
        self.__sessions[original_ip] = [4, None, [spi, crypt_algo, crypt_key]]
        
        must_end = time.time() + timeout
        while time.time() < must_end:
            if self.__sessions[original_ip][0] > 4: 
                return True
            time.sleep(0.1)
        
        del self.__sessions[original_ip]
        return False
        
    def __send(self, socket: Socket, message: bytes) -> None:
        # logger.info(f"Sending {socket.totuple()} {message}")
        self.__server_socket.sendto(message, socket.totuple())
