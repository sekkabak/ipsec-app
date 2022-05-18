from Host import Host
from Socket import Socket

if __name__ == '__main__':
    
    
    
    host = Host('127.0.0.11', 10000, Socket('127.0.0.12', 10000))
    host.send("test", "127.0.0.14", 10000)
