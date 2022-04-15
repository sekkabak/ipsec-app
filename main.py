from __future__ import print_function
import math
import socket
import sys
import pyDHE
from bob import send
from threading import Thread
# Variables Used

HOST="127.0.0.1"
PORT=500
bufferSize=2048
#UDP 500
#one function, multiprocesing lib  dictionary, array
def listener():
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.bind((HOST, PORT))
                while True:
                    #print("connected by", address)
                    bytesAddressPair = s.recvfrom(bufferSize)
                    #message = bytesAddressPair[0]
                    address = bytesAddressPair[1]
                   # print("Message: ", message)
                    print("Connected by: ", format(address))
                    alice = pyDHE.new(14)
                    bob_pub_key_bytes = s.recv(2048)
                    #print(format(bob_pub_key_bytes))
                    bob_pub_key=int.from_bytes(bob_pub_key_bytes, sys.byteorder, signed=False)
                    shared_key = alice.update(bob_pub_key)
                    alice_pub_key = alice.getPublicKey()
                    alice_pub_key_bytes = alice_pub_key.to_bytes(math.ceil(alice_pub_key.bit_length()), sys.byteorder, signed=False)
                    s.sendto(alice_pub_key_bytes,(address))
                    print("Shared key: ", shared_key)

if __name__ == "__main__":
        Thread(target=listener).start()
        Thread(target=send).start()
