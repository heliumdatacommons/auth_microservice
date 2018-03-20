import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading
import psycopg2
from Crypto import Random
from Crypto.Cipher import AES

class Crypt(object):
    algo = AES
    def __init__(self, key):
        self.key = key
        self.pad_char = sum(list(key)) % (ord("z")-ord("a") + ord("a"))
        self.random = Random.new()

    def encrypt(self, s):
        if len(s) % AES.block_size != 0:
            # pad
            s = s + (AES.block_size - (len(s) % AES.block_size)) * self.pad_char
        iv = self.random.read(AES.block_size)
        self.


class Database(object):
    def __init__(self, keyfile_path=None):
        if not keyfile_path:
            raise RuntimeError("no keyfile specified, exiting")
        with open(keyfile, "rb") as f:
            key = f.read()
        self.crypt = Crypt(key)

class MyPublicRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path
        
        self.send_response(200)
        self.send_header("Content-type","text/html")
        self.end_headers()
        message = "Response from PUBLIC server"
        self.wfile.write(bytes(message,"utf8"))
        return


def private_server(address):
    httpd = HTTPServer(address, MyPrivateRequestHandler)
    httpd.serve_forever()
def public_server(address):
    httpd = HTTPServer(address, MyPublicRequestHandler)
    httpd.serve_forever()

def run():
    public_ip = sys.argv[1]
    private_ip = sys.argv[1]
    t1 = threading.Thread(target=private_server, args=((private_ip, 2468),))
    t2 = threading.Thread(target=public_server, args=((public_ip, 2468),))
    t1.start()
    t2.start()

    t1.join()
    t2.join()

run()

