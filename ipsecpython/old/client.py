import socket
from flask import Flask
from gevent.pywsgi import WSGIServer
from Host import Host

app = Flask(__name__)
local_ip = '127.0.0.1'
local_port = 0


@app.route('/')
def index():
    return ''


@app.route('/send_test', methods=['POST'])
def send_test():
    host = Host(b'1234567890123456', ('127.0.0.1', 51234), local_port)
    host.send("test", "127.0.0.1", 12345)
    return ""


if __name__ == '__main__':
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('localhost', 0))
    local_port = sock.getsockname()[1]
    sock.close()
    print("http://" + local_ip + ":" + str(local_port), flush=True)
    http_server = WSGIServer((local_ip, local_port), app)
    http_server.serve_forever()
