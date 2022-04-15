from Middleware.Socket import Socket
from Middleware.Transceiver import Transceiver

if __name__ == '__main__':
    a = Transceiver('192.168.0.113', 11111, 11112)
    a.add_to_arp(Socket('192.168.0.113', 11113), "255.255.255.255")
    a.start()
