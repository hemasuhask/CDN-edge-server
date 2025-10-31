import socket
import threading
import ssl
from queue import Queue

HOST = ''
PORT = 4445

context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain(certfile="./certs/cdn_cert.pem", keyfile="./certs/cdn_key.pem")

soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
soc.bind((HOST, PORT))
soc.listen(9)
print('Socket listening on port', PORT)

connection_pool = Queue(maxsize=10)

def get_connection(origin_host, origin_port):
    try:
        conn = connection_pool.get_nowait()
        conn.send(b"")
        return conn
    except Exception:
        conn = socket.create_connection((origin_host, origin_port))
        return ssl.wrap_socket(conn)

def release_connection(conn):
    try:
        connection_pool.put_nowait(conn)
    except Exception:
        conn.close()

def client_to_server(source, dest):
    while True:
        data_chunks = []
        chunk = source.recv(1024)
        data_chunks.append(chunk)
        while len(chunk) == 1024:
            chunk = source.recv(1024)
            if not chunk:
                break
            data_chunks.append(chunk)
        
        data = b"".join(data_chunks)
        if not data:
            print("No client response, closing connection")
            source.close()
            return
        
        data = data.replace(b"Connection: keep-alive", b"Connection: close")
        print("SENDING TO SERVER:", len(data), "bytes")
        dest.sendall(data)

def server_to_client(source, dest):
    while True:
        data_chunks = []
        chunk = source.recv(1024)
        data_chunks.append(chunk)
        while len(chunk) == 1024:
            chunk = source.recv(1024)
            if not chunk:
                break
            data_chunks.append(chunk)
        
        data = b"".join(data_chunks)
        if not data:
            print("No server response, closing connection")
            source.close()
            return
        
        print("SENDING TO CLIENT:", len(data), "bytes")
        dest.sendall(data)

def handle_new(conn, address):
    print(f"Connected with {address[0]}:{address[1]}")
    ssl_client_conn = context.wrap_socket(conn, server_side=True)
    try:
        origin_socket = get_connection('152.3.103.25', 443)
        client_thread = threading.Thread(target=client_to_server, args=(ssl_client_conn, origin_socket))
        client_thread.start()
        server_thread = threading.Thread(target=server_to_client, args=(origin_socket, ssl_client_conn))
        server_thread.start()
        client_thread.join()
        server_thread.join()
    finally:
        release_connection(origin_socket)

while True:
    conn, address = soc.accept()
    threading.Thread(target=handle_new, args=(conn, address)).start()