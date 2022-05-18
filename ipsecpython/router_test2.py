from Router import Router
from Socket import Socket


if __name__ == '__main__':
    a = Router('127.0.0.13', 10000, 10001)
    a.add_to_static_routes(Socket('127.0.0.11', 10000), "255.255.255.255") # host 1
    a.add_to_static_routes(Socket('127.0.0.12', 10000), "255.255.255.255") # router 2
    a.start()
    # create_tunnel 127.0.0.13