from Host import Host
from Socket import Socket

if __name__ == '__main__':
    host = Host('127.0.0.17', 10000, Socket('127.0.0.16', 10000))
    # host.ping("127.0.0.48")
    host.listen_forever()