from Socket import Socket
from Transceiver import Transceiver

# router 1
if __name__ == '__main__':
    a = Transceiver('127.0.0.13', 10000, 10001)
    a.add_to_static_routes(Socket('127.0.0.14', 80), "255.255.255.255") # host 2
    a.add_to_static_routes(Socket('127.0.0.12', 10000), "255.255.255.252") # router 1
    a.send_ike("test", ('127.0.0.12', 500))
    a.start()
