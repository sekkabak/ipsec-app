from pyexpat.errors import messages
import threading
from scapy.compat import raw
from scapy.layers.inet import IP, TCP
from scapy.layers.ipsec import SecurityAssociation, ESP
from scapy.packet import Raw
from multiprocessing import Process
import pickle
import socket
import json
import base64
from Socket import Socket

import pickle
import socket
import time
import sys
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
logger = logging.getLogger("host")
logger.setLevel(logging.DEBUG)


class Host:
    __interface: str
    __listen_port: int
    __network_gateway: Socket

    __ping_response: bool = False
    t_listener: threading.Thread
    messages_queue: list
    tmp_file: bytes

    def __init__(self, interface: str, listen_port: int, network_gateway: Socket):
        self.__interface = interface
        self.__listen_port = listen_port
        self.__network_gateway = network_gateway
        self.messages_queue = []

        self.t_listener = threading.Thread(target=self.__listener, daemon=True)
        self.t_listener.start()

    def __listener(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_socket.bind((self.__interface, self.__listen_port))

        try:
            while True:
                message, address = server_socket.recvfrom(33000)

                packet = IP(message)
                layers = self.__scapy_get_layers(packet)
                layers_names = [x.name for x in layers]
                logger.error(f"Packet came with layers: {layers_names}")
                
                if layers_names == ['IP', 'ICMP', 'Raw']:
                    raw_data = raw(packet[Raw])
                    if raw_data == b'ping':
                        logger.error(f"Sending pong packet to {packet.src}")
                        self.send_ICMP_packet(packet.src, b'pong')
                    elif raw_data == b'pong':
                        self.__ping_response = True
                    continue
                else:
                    data = pickle.loads(packet[Raw].load)
                    try:
                        if data["part"] == 0:
                            self.tmp_file = data["data"]
                        elif data["part"] == -1:
                            self.tmp_file += data["data"]
                            data = pickle.loads(self.tmp_file)

                            if data[0:3] == b'ID3':
                                print("Music file detected")
                                self.messages_queue.append({"type":"mp3","message":base64.b64encode(data).decode('ascii')})
                            else:
                                print(f"adding file of len:{len(data)}")
                                self.messages_queue.append({"type":"file","message":base64.b64encode(data).decode('ascii')})
                        else:
                            self.tmp_file += data["data"]
                            print(f"adding part of the file", flush=True)
                        continue
                    except Exception as e:
                        # not file
                        pass
                    
                    self.messages_queue.append(json.loads(data))
                    sys.stdout.flush()
        except Exception as e:
            self.messages_queue.clear()
            # ignore

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

        i = 0
        end = (len(obj) // 32768) + 1
        if i+1 == end:
            p = IP(src=src_ip, dst=dst_ip)
            p /= TCP(sport=src_port, dport=dst_port)
            p /= Raw(obj)
    
            s.sendto(raw(p), (network_gateway_ip, network_gateway_port))
            s.close()
            return
        
        # print(f"Len of file: {len(obj)}")
        while i < end:
            if i+1 == end:
                data = obj[i*32768:]
                # print(f"{i*32768}:{len(obj)}")
            else:
                data = obj[i*32768:(i+1)*32768]
                # print(f"{i*32768}:{(i+1)*32768}")

            # creating encapsulated packet
            p = IP(src=src_ip, dst=dst_ip)
            p /= TCP(sport=src_port, dport=dst_port)
            if i+1 == end:
                p /= Raw(pickle.dumps({"part": -1, "data": data}))
            else:
                p /= Raw(pickle.dumps({"part": i, "data": data}))

            # sending encapsulated packet
            # print(f"{i}", flush=True)
            s.sendto(raw(p), (network_gateway_ip, network_gateway_port))
            time.sleep(0.1)
            i+=1

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

    def update_gateway(self, ip):
        self.__network_gateway = Socket(ip, self.__network_gateway.port)
        return 'ok'

    def get_update_queque(self):
        tmp = self.messages_queue.copy()
        self.messages_queue.clear()
        return json.dumps(tmp)

    def listen_forever(self):
        self.t_listener.join()
