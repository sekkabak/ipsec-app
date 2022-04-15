import Middleware.Socket
import Middleware.Transceiver

if __name__ == '__main__':
    a = Middleware.Transceiver.Transceiver('192.168.0.113', 11113, 11114)
    a.add_to_arp(Middleware.Socket.Socket('192.168.0.113', 11111), "255.255.255.255")
    a.test(Middleware.Socket.Socket('192.168.0.113', 11111), 'test'.encode('utf-8'), 5)
