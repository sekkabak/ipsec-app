from scapy.compat import raw
from scapy.layers.inet import IP, TCP
from scapy.layers.ipsec import SecurityAssociation, ESP
from scapy.packet import Raw


def print_hi(name):
    print(f'Hi, {name}')

def scapy_example():
    sa = SecurityAssociation(ESP, spi=0xdeadbeef, crypt_algo='AES-CBC', crypt_key='sixteenbytes key')
    p = IP(src='1.1.1.1', dst='2.2.2.2')
    p /= TCP(sport=45012, dport=80)
    p /= Raw(b'testdata')
    p = IP(raw(p))
    print(p)


if __name__ == '__main__':
    scapy_example()

