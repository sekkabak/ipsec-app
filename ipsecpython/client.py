import pickle
import json
import base64
import socket
from flask import Flask, request, make_response
from flask_cors import CORS
from gevent.pywsgi import WSGIServer
from Host import Host
from Socket import Socket

app = Flask(__name__)
CORS(app)

gateway_ip = '127.0.0.48'
local_ip = '127.0.0.49'

# gateway_ip = '127.0.0.16'
# local_ip = '127.0.0.17'

local_port = 10000
host = Host(local_ip, local_port, Socket(gateway_ip, local_port))


@app.route('/')
def index():
    return ''

@app.route('/info')
def info():
    return json.dumps({
        "gateway_ip": gateway_ip,
        "local_ip": local_ip,
        "local_port": local_port
    })

@app.route('/ping/<ip>', methods=['GET', 'POST'])
def send_ping(ip):
    return host.ping(ip)

@app.route('/update_gateway/<ip>', methods=['GET', 'POST'])
def update_gateway(ip):
    return host.update_gateway(ip)  

@app.route('/send_message', methods = ['GET', 'POST'])
def send_message():
    content = request.get_json(silent=True)
    type = content["message_type"]
    message = content["message"]
    ip = content["to"]
    host.send(pickle.dumps(json.dumps({"type":type, "message": message})), ip, local_port)
    return content

@app.route('/send_file/<ip>', methods = ['POST'])
def send_file(ip):
    file = request.files.get('file', '')
    host.send(pickle.dumps(file.read()), ip, local_port)
    return 'ok'

@app.route('/get_updates', methods = ['GET'])
def get_updates():
    return host.get_update_queque()


if __name__ == '__main__':
    import sys
    
    try:
        # app.run(debug=True, port=5000)

        # sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # sock.bind(('127.0.0.1', 5000))
        # middleware_port = sock.getsockname()[1]
        # sock.close()
        middleware_port = 5000
        print("http://" + '192.168.94.128' + ":" + str(middleware_port), flush=True)
        http_server = WSGIServer(('192.168.94.128', middleware_port), app)
        http_server.serve_forever()
    except KeyboardInterrupt:
        http_server.close()
        sys.exit(0)
