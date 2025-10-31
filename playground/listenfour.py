import socket
import threading
import ssl
from queue import Queue
import time
from urllib.parse import urlparse

HOST = ''
PORT = 4445

context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain(certfile="./certs/cdn_cert.pem", keyfile="./certs/cdn_key.pem")
context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20') 
context.set_ecdh_curve('prime256v1') 
context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 

cache = {}
cache_lock = threading.Lock()
connection_pool = Queue(maxsize=10)

def is_cacheable(response_data):
    try:
        headers, _ = response_data.split(b'\r\n\r\n', 1)
        header_str = headers.decode('latin-1').lower()
        
        if 'cache-control: no-store' in header_str:
            return False
            
        content_type = None
        for line in header_str.split('\r\n'):
            if line.startswith('content-type:'):
                content_type = line.split(':', 1)[1].strip()
                break
                
        cacheable_types = {
            'text/html', 'text/css', 'application/javascript',
            'image/jpeg', 'image/png', 'image/gif', 'application/x-font-woff'
        }
        return any(ct in content_type for ct in cacheable_types) if content_type else False
    except Exception:
        return False

def handle_new(conn, address):
    try:
        print(f"Connected with {address[0]}:{address[1]}")
        ssl_client = context.wrap_socket(conn, server_side=True)

        request = ssl_client.recv(8192)
        if not request:
            ssl_client.close()
            return

        try:
            path = request.split(b' ', 2)[1].split(b'?', 1)[0].decode('latin-1')
        except (IndexError, UnicodeDecodeError):
            ssl_client.close()
            return

        with cache_lock:
            cached_entry = cache.get(path)
            if cached_entry and cached_entry['expiry'] > time.time():
                print(f"Cache HIT for {path}")
                ssl_client.sendall(cached_entry['data'])
                ssl_client.close()
                return

        try:
            origin = socket.create_connection(('152.3.103.25', 443))
            origin_ssl = ssl.wrap_socket(origin, ssl_version=ssl.PROTOCOL_TLS)
        except Exception as e:
            print(f"Origin connection failed: {e}")
            ssl_client.close()
            return

        origin_ssl.send(request)
        response_chunks = []
        while True:
            chunk = origin_ssl.recv(4096)
            if not chunk:
                break
            response_chunks.append(chunk)
        response = b''.join(response_chunks)

        if is_cacheable(response):
            with cache_lock:
                cache[path] = {
                    'data': response,
                    'expiry': time.time() + 3600 
                }
            print(f"Cached {path}")

        ssl_client.sendall(response)
        origin_ssl.close()
        ssl_client.close()

    except Exception as e:
        print(f"Error handling connection: {e}")
    finally:
        if 'ssl_client' in locals():
            ssl_client.close()
        if 'origin_ssl' in locals():
            origin_ssl.close()

soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
soc.bind((HOST, PORT))
soc.listen(9)

print(f"Secure proxy listening on {PORT}")
while True:
    conn, addr = soc.accept()
    threading.Thread(target=handle_new, args=(conn, addr)).start()