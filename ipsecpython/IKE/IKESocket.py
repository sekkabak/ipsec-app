from __future__ import annotations

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

import sys, json
import asyncio

import logging
 
logger = logging.getLogger("ike")
logger.setLevel(logging.DEBUG)


class IKESocket:
    __server_socket: socket.socket
    # __ike: IKEService
    
    async def __aenter__(self, interface: str, ike_port: int):
        logger.info(f"Initializing IKESocket")
        self.loop = asyncio.get_event_loop()
        # self.__ike = ike
        
        self.__server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.__server_socket.bind((interface, ike_port))
        fcntl.fcntl(self.__server_socket, fcntl.F_SETFL, os.O_NONBLOCK)
             
        return self

    async def __aexit__(self, *args, **kwargs):
        await self.__server_socket.close()
        
    async def send(self, socket: Socket, message: bytes) -> None:
        logger.info(f"Sending {socket} {message}")
        await self.__server_socket.sendto(message, socket.totuple())

    async def receive(self) -> tuple[bytes, tuple[str, int]]:
        return await self.__server_socket.recvfrom(1024)
    
    def tryreceive(self) -> tuple[bytes, tuple[str, int]]:
        try:
            message, address = self.__server_socket.recvfrom(1024)
        except socket.error as e:
            err = e.args[0]
            if err == errno.EAGAIN or err == errno.EWOULDBLOCK:
                return None, None
            else:
                logger.error(f"Error: {e}")
        else:
            return message, address
