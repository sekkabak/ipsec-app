import pickle
import socket
import time
from multiprocessing import Process, Manager, Queue
from typing import Union, Optional

from scapy.compat import raw
from scapy.layers.inet import IP, TCP
from scapy.layers.ipsec import SecurityAssociation, ESP
from scapy.packet import Raw

from Middleware.StaticRouteRecord import StaticRouteRecord
from Middleware.Socket import Socket
from Middleware.Tunnel import Tunnel

if __name__ == '__main__':
    sa = SecurityAssociation(ESP, spi=0xdeadbeef, crypt_algo='AES-CBC',
                             crypt_key=b'sixteenbytes key')
    p = IP(src='1.1.1.1', dst='2.2.2.2')
    p /= TCP(sport=45012, dport=80)
    p /= Raw(b'testdata')

    e = IP(src='0.0.0.0', dst='9.9.9.9')
    e /= Raw(sa.encrypt(p))

    res = sa.decrypt(IP(e.payload.load))


