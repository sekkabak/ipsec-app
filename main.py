from __future__ import print_function
import math
import socket
import sys
from time import sleep

from Middleware.DHE import DHE
from threading import Thread


def listener():
    print("Listen start")
    sys.stdout.flush()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as ss:
        ss.bind(("127.0.0.2", 5000))

        alice = DHE(18)
        key = alice.negotiate(ss, ("127.0.0.3", 5000))

        print("p2 Shared key: ", key)
        sys.stdout.flush()

        # while True:
        #     # print("connected by", address)
        #     bytesAddressPair = ss.recvfrom(2048)
        #     # message = bytesAddressPair[0]
        #     address = bytesAddressPair[1]
        #     # print("Message: ", message)
        #     print("Connected by: ", format(address))
        #     sys.stdout.flush()
        #     alice = DHE(14)
        #     bob_pub_key_bytes = ss.recv(2048)
        #     # print(format(bob_pub_key_bytes))
        #     bob_pub_key = int.from_bytes(bob_pub_key_bytes, sys.byteorder, signed=False)
        #     shared_key = alice.update(bob_pub_key)
        #     alice_pub_key = alice.getPublicKey()
        #     alice_pub_key_bytes = alice_pub_key.to_bytes(math.ceil(alice_pub_key.bit_length()), sys.byteorder,
        #                                                  signed=False)
        #     ss.sendto(alice_pub_key_bytes, (address))
        #     print("Shared key: ", shared_key)

def send():
    print("Send start")
    sys.stdout.flush()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as ss:
        ss.bind(("127.0.0.3", 5000))

        alice = DHE(18)
        key = alice.negotiate(ss, ("127.0.0.2", 5000))

        print("p2 Shared key: ", key)
        sys.stdout.flush()

        # bob = DHE(14)
        # ss.sendto(str.encode('Working'), ("127.0.0.2", 5000))
        # bob_pub_key = bob.getPublicKey()
        # bob_pub_key_bytes = bob_pub_key.to_bytes(math.ceil(bob_pub_key.bit_length() / 8), sys.byteorder, signed=False)
        # ss.sendto(bob_pub_key_bytes, ("127.0.0.2", 5000))
        # alice_pub_key_bytes = ss.recvfrom(2048)
        # alice_pub_key = int.from_bytes(alice_pub_key_bytes, byteorder='little')
        # shared_key = bob.update(alice_pub_key)
        # print("Shared key: ", shared_key)
        # sys.stdout.flush()


if __name__ == "__main__":
    Thread(target=listener).start()
    Thread(target=send).start()
