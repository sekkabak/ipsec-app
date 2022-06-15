from http.server import BaseHTTPRequestHandler, HTTPServer
import time

class MyServer(BaseHTTPRequestHandler):
    file = ""
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        with open(self.file,'r',encoding = 'utf-8') as f:
            self.wfile.write(f.read().encode('utf-8'))
    def log_message(self, format, *args):
        return