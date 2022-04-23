from scapy.compat import raw
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.ipsec import SecurityAssociation, ESP, AH
from scapy.packet import Raw
from scapy.sendrecv import send, sr


def print_hi(name):
    print(f'Hi, {name}')


def scapy_example():
    #
    sa = SecurityAssociation(ESP, spi=0xdeadbeef, crypt_algo='AES-CBC', crypt_key=b'sixteenbytes key')
    p = IP(src='192.168.0.113', dst='192.168.0.122')
    p /= UDP(sport=23456, dport=65432)
    p /= Raw(b'testdata')
    p = IP(raw(p))
    e = sa.encrypt(p)
    print(e)
    #

    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", 65432))
    s.sendall(raw(e))
    s.close()

    r = send(e)
    print(r)


if __name__ == '__main__':
    scapy_example()

