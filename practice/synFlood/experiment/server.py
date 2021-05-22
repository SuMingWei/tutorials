import sys
import socketserver
import http.server

class ThreadedHTTPServer(socketserver.ThreadingMixIn,http.server.HTTPServer):
    daemon_threads = True

# port = int(sys.argv[1])
server = ThreadedHTTPServer(('10.0.1.1',5001),http.server.SimpleHTTPRequestHandler)
try:
    server.serve_forever()
except KeyboardInterrupt:
    pass
