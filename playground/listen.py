import socket
import threading

HOST = ''
PORT = 4445

soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
soc.bind((HOST, PORT))
soc.listen(9)  # Start listening for connections
print('Socket listening on port', PORT)


def client_to_server(source, dest):
    while True:
        data_chunks = []
        chunk = source.recv(1024)
        data_chunks.append(chunk)
        while len(chunk) == 1024:
            chunk = source.recv(1024)
            #print("CHUNK RECIEVED", len(chunk), chunk)
            if not chunk:
                break
            data_chunks.append(chunk)

        data = b"".join(data_chunks)
        if not data:
            print("No client response, closing connection")
            source.close()
            return

        print("SENDING:", len(data), "bytes")

        dest.sendall(data)

def server_to_client(source, dest):
    while True:
        data_chunks = []
        chunk = source.recv(1024)
        data_chunks.append(chunk)
        while len(chunk) == 1024:
            chunk = source.recv(1024)
            print("CHUNK RECIEVED FROM SERVER", len(chunk))
            if not chunk:
                break
            data_chunks.append(chunk)

        data = b"".join(data_chunks)
        if not data:
            print("No server response, closing connection")
            source.close()
            return

        print("SENDING:", len(data), "bytes")

        dest.sendall(data)





def handle_new(conn, address):
    print(f"Connected with {address[0]}:{address[1]}")

    # Connect to cs.duke.edu (Origin Server)
    origin_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    origin_socket.settimeout(5)  # Prevent infinite waiting
    origin_socket.connect(('152.3.103.25', 443))
    print("Connected to cs.duke.edu")

    socket.setdefaulttimeout(5)
    

    client_thread = threading.Thread(target=client_to_server, args=(conn, origin_socket))
    client_thread.start()

    server_thread = threading.Thread(target=server_to_client, args=(origin_socket, conn))
    server_thread.start()



conn, address = soc.accept()
handle_new(conn, address)
