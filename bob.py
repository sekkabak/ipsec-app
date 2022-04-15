from __future__ import print_function
import math
import socket
import sys
import pyDHE
# Variables Used

HOST="127.0.0.1"
PORT=500
def send():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as ss:
        #s.connect((HOST, PORT))
        bob = pyDHE.new(14)
        ss.sendto(str.encode('Working'), (HOST, PORT))
        bob_pub_key = bob.getPublicKey()
        bob_pub_key_bytes = bob_pub_key.to_bytes(math.ceil(bob_pub_key.bit_length()/8),sys.byteorder, signed=False)
        #print(bob_pub_key_bytes)
        ss.sendto(bob_pub_key_bytes,(HOST, PORT))
        alice_pub_key_bytes = ss.recv(2048)
        alice_pub_key = int.from_bytes(alice_pub_key_bytes, sys.byteorder, signed=False)
        shared_key = bob.update(alice_pub_key)
        print("Shared key: ", shared_key)
