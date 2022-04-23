from scapy.compat import raw
from scapy.layers.inet import IP, TCP
from scapy.layers.ipsec import SecurityAssociation, ESP
from scapy.packet import Raw
from scapy.sendrecv import send, sr
import socket

def print_hi(name):
    print(f'Hi, {name}')

def scapy_example():
    HOST = "127.0.0.1"  # Standard loopback interface address (localhost)
    PORT = 65432  # Port to listen on (non-privileged ports are > 1023)
    sa = SecurityAssociation(ESP, spi=0xdeadbeef, crypt_algo='AES-CBC', crypt_key=b'sixteenbytes key')

    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, PORT))
    s.listen(1)
    conn, addr = s.accept()
    while 1:
        data = conn.recv(1024)
        if not data:
            break
        print(IP(data))
        d = sa.decrypt(IP(data))
        print(d)

    conn.close()


if __name__ == '__main__':
    scapy_example()

