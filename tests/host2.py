from Middleware.Host import Host
from Middleware.Socket import Socket

if __name__ == '__main__':
    host = Host('127.0.0.14', 80, Socket('127.0.0.13', 10000))
    host.start()
