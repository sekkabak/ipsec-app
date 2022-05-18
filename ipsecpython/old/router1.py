from Socket import Socket
from Transceiver import Transceiver

# router 1
if __name__ == '__main__':
    a = Transceiver('127.0.0.12', 10000, 10001)
    a.add_to_static_routes(Socket('127.0.0.11', 80), "255.255.255.255") # host 1
    a.add_to_static_routes(Socket('127.0.0.13', 10000), "255.255.255.252") # router 2
    a.start()
