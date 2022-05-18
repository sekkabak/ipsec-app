from __future__ import annotations
from audioop import add

import errno
import fcntl
import os
import pickle
import socket
import threading
import time

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
    __tunnels: list[Tunnel]
    __server_socket: socket.socket
    __sessions: dict
    __dh: DiffieHellman
    
    def __init__(self, interface: str, tunnels: list[Tunnel]) -> None:
        logger.info(f"Initializing IKE")
        self.__interface = interface
        self.__tunnels = tunnels
        self.__sessions = dict()
        
        self.__dh = DiffieHellman()

        self.__server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.__server_socket.bind((self.__interface, self.__ike_port))
        fcntl.fcntl(self.__server_socket, fcntl.F_SETFL, os.O_NONBLOCK)
        
        t_listener = threading.Thread(target=self.__listener, daemon=True)
        t_listener.start()
        
    def __listener(self):
        while True:
            try:
                message, address = self.__server_socket.recvfrom(1024)
                ike_socket = Socket(address[0], 500)
                sess = self.__sessions.get(address[0])
                logger.info(f"Message to IKE came from {address}")
                
                if message == b'DH init':
                        self.__sessions[ike_socket.ip] = [1, None]
                        self.__send(ike_socket, self.__dh.public_key)
                        logger.info(f"Sended DH public key to {address[0]}")
                elif sess != None:
                    if sess[0] == 1: # diffiehellman fase
                        other_key = int.from_bytes(message, "big")  
                        shared_key = self.__dh.derivate(other_key=other_key)
                        logger.info(f"IKE estabilished DH tunnel with {address[0]}")
                        self.__sessions[address[0]] = [2, shared_key]
                    elif sess[0] == 2 and message == b'IPsec IKE':  # IKE INIT fase
                        sess[0] = 3
                        self.__sessions[address[0]] = sess
                    elif sess[0] == 3: # IKE fase
                        key = self.__sessions[ike_socket.ip][1]
                        
                        cipher = Cipher(algorithms.AES(key[:32]), modes.ECB())
                        decryptor = cipher.decryptor()
                        data = decryptor.update(message) + decryptor.finalize()
                        data = data[:-data[-1]]
                        spi, crypt_algo, crypt_key = pickle.loads(data)
                        logger.info(f"spi: {spi}")
                        logger.info(f"crypt_algo: {crypt_algo}")
                        logger.info(f"crypt_key: {crypt_key}")
                        
                        # TODO check if spi is ok
                        self.__send(ike_socket, b'OK')
                        tunnel = Tunnel()
                        tunnel.spi = spi
                        tunnel.crypt_algo = crypt_algo
                        tunnel.crypt_key = crypt_key
                        tunnel.dst_ip = ike_socket.ip
                        tunnel.dst_port = 10000
                        tunnel.network_ip = '127.0.0.13'
                        tunnel.network_port = 10000
                        self.__tunnels.append(tunnel)
                        logger.info(f"IPsec tunnel to {ike_socket.ip} has been created")

                    elif sess[0] == 4 and message == b'OK': # IKE rcv respond
                        tunnel = Tunnel()
                        tunnel.spi, tunnel.crypt_algo, tunnel.crypt_key = sess[2]
                        
                        tunnel.dst_ip = ike_socket.ip
                        tunnel.dst_port = 10000
                        tunnel.network_ip = '127.0.0.13'
                        tunnel.network_port = 10000
                        self.__tunnels.append(tunnel)
                        logger.info(f"IPsec tunnel to {ike_socket.ip} has been created")
            except socket.error as e:
                err = e.args[0]
                if err == errno.EAGAIN or err == errno.EWOULDBLOCK:
                    # no data
                    pass
                else:
                    # a "real" error occurred
                    logger.error(e)

    def estabilish_DH_channel(self, ip: str, timeout = 5):
        ike_socket = Socket(ip, 500)
        
        self.__send(ike_socket, "DH init".encode("utf-8"))
        logger.info(f"Sended DH init packet to {ip}")
        
        self.__send(ike_socket, self.__dh.public_key)
        logger.info(f"Sended DH public key to {ip}")
        self.__sessions[ike_socket.ip] = [1, None]
        
        must_end = time.time() + timeout
        while time.time() < must_end:
            if self.__sessions[ike_socket.ip][0] > 1: 
                return True
            time.sleep(0.1)
        
        del self.__sessions[ike_socket.ip]
        return False
    
    def propose_IPsec_keys(self, ip: str, timeout = 5):
        ike_socket = Socket(ip, 500)
        
        if self.__sessions[ike_socket.ip] == None or self.__sessions[ike_socket.ip][0] < 2:
            logger.error(f"{self.__sessions[ike_socket.ip]}")
            return False
        
        key = self.__sessions[ike_socket.ip][1]
        
        self.__send(ike_socket, "IPsec IKE".encode("utf-8"))
        logger.info(f"Sended IPsec IKE init packet to {ip}")

        cipher = Cipher(algorithms.AES(key[:32]), modes.ECB())
        encryptor = cipher.encryptor()
        
        crypt_algo = 'AES-CBC'
        spi = int.from_bytes(os.urandom(8), "big")
        crypt_key = os.urandom(16)
        
        data = pickle.dumps([spi, crypt_algo, crypt_key], 0)
        length = 16 - (len(data) % 16)
        data += bytes([length])*length
        
        ct = encryptor.update(data) + encryptor.finalize()
        
        self.__send(ike_socket, ct)
        logger.info(f"Sended IPsec IKE keys to {ip}")
        
        self.__sessions[ike_socket.ip] = [4, None, [spi, crypt_algo, crypt_key]]
        
        must_end = time.time() + timeout
        while time.time() < must_end:
            if self.__sessions[ike_socket.ip][0] > 4: 
                return True
            time.sleep(0.1)
        
        del self.__sessions[ike_socket.ip]
        return False
        
    def __send(self, socket: Socket, message: bytes) -> None:
        logger.info(f"Sending {socket.totuple()} {message}")
        self.__server_socket.sendto(message, socket.totuple())
