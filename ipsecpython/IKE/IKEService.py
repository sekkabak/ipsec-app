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

import IKE

import logging
logger = logging.getLogger("ike")
logger.setLevel(logging.DEBUG)


class IKEService:
    ike_port: int = 500
    interface: str
    router: Router
    ikeSocket: IKE.IKESocket
    sessions: dict
    
    async def __aenter__(self, interface: str, router: Router):
        logger.info(f"Initializing IKE")
        self.loop = asyncio.get_event_loop()
        self.interface = interface
        self.router = router

        self.ikeSocket = IKE.IKESocket(self)
        asyncio.create_task(self.__watch_for_init_packets())

        return self

    async def __aexit__(self, *args, **kwargs):
        await self.ikeSocket.__aexit__(*args, **kwargs)
    
    async def estabilish_DH_channel(self, ip: str):
        dh = DiffieHellman()
        ike_socket = Socket(ip, 500)
        
        await self.loop.run_until_complete(self.ikeSocket.send(ike_socket, "DH init".encode("utf-8")))
        logger.info(f"Sended DH init packet to {ip}")
        
        await self.loop.run_until_complete(self.ikeSocket.send(ike_socket, dh.public_key))
        logger.info(f"Sended DH public key to {ip}")
        
        other_key_bytes = await self.loop.run_until_complete(self.ikeSocket.receive())
        other_key = int.from_bytes(other_key_bytes, "big")  
        shared_key = dh.derivate(other_key=other_key)
        logger.info(f"IKE estabilished DH tunnel with {ip}")
        return 1, "test", "test".encode("utf-8")

    async def receive_DH_channel(self, ip: str):
        dh = DiffieHellman()
        ike_socket = Socket(ip, 500)
        
        other_key_bytes = await self.loop.run_until_complete(self.ikeSocket.receive())
        other_key = int.from_bytes(other_key_bytes, "big")
        
        await self.loop.run_until_complete(self.ikeSocket.send(ike_socket, dh.public_key))
        logger.info(f"Sended DH public key to {ip}")

        shared_key = dh.derivate(other_key=other_key)
        logger.info(f"IKE estabilished DH tunnel with {ip}")
        self.sessions[ip] = [2, shared_key]
    
    async def __watch_for_init_packets(self, seconds = 5):
        while True:
            await asyncio.sleep(seconds)
            message, address = self.ikeSocket.tryreceive
            if message == None:
                continue
            
            ip = address[0]
            if message == b'DH init':
                self.sessions[ip] = [1, None]
                self.receive_DH_channel(self, ip)
            
            if message == b'IPsec IKE':
                pass
