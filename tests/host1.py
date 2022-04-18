from Middleware.Host import Host
from Middleware.Socket import Socket

if __name__ == '__main__':
    host = Host('127.0.0.11', 80, Socket('127.0.0.12', 10000))
    host.send("test", "127.0.0.14", 80)
