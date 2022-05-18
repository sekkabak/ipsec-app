from Host import Host
from Socket import Socket

if __name__ == '__main__':
    
    
    
    host = Host('127.0.0.14', 10000, Socket('127.0.0.13', 10000))
    host.start()
