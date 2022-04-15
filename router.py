from Middleware.Socket import Socket
from Middleware.Transceiver import Transceiver

if __name__ == '__main__':
    a = Transceiver('127.0.0.1', 11111, 11112)
    a.add_to_arp(Socket('127.0.0.2', 11113), "255.255.255.255")
    a.start()
