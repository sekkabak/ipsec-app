import socket
from flask import Flask, request, make_response
from flask_cors import CORS
from gevent.pywsgi import WSGIServer
from Host import Host

app = Flask(__name__)
CORS(app)
local_ip = '127.0.0.1'
local_port = 0


@app.route('/')
def index():
    return ''

@app.route('/send_message', methods=['POST'])
def send_test():
    # host = Host(b'1234567890123456', ('127.0.0.1', 51234), local_port)
    # host.send("test", "127.0.0.1", 12345)
    return str(request.get_json())

@app.route('/users/<user_id>', methods = ['GET', 'POST', 'DELETE'])
def user(user_id):
    if request.method == 'GET':
        """return the information for <user_id>"""
    if request.method == 'POST':

        """modify/update the information for <user_id>"""

        # you can use <user_id>, which is a str but could
        # changed to be int or whatever you want, along
        # with your lxml knowledge to make the required
        # changes
        data = request.data # a multidict containing POST data
        return data

@app.route('/files/<file_id>', methods = ['GET', 'POST', 'DELETE'])
def file(file_id):
    if request.method == 'GET':
        """siema"""
    if request.method == 'POST':
        data = request.data
        return data



if __name__ == '__main__':
    # app.run(debug=True)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('localhost', 5000))
    local_port = sock.getsockname()[1]
    sock.close()
    print("http://" + local_ip + ":" + str(local_port), flush=True)
    http_server = WSGIServer((local_ip, local_port), app)
    http_server.serve_forever()
