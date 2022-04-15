import Middleware.Socket
import Middleware.Transceiver

if __name__ == '__main__':
    a = Middleware.Transceiver.Transceiver('127.0.0.2', 11113, 11114)
    a.add_to_arp(Middleware.Socket.Socket('127.0.0.1', 11111), "255.255.255.255")
    a.test(Middleware.Socket.Socket('127.0.0.1', 11111), 'test'.encode('utf-8'), 1)
