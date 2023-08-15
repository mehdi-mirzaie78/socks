import socket
import threading
import select
import subprocess
import argparse
from random import randint

SOCKS_VERSION = 5


class Proxy:

    def __init__(self, username, password, port=None):
        result = subprocess.run(['hostname', '-I'], stdout=subprocess.PIPE)
        self.host = result.stdout.decode('utf-8').split()[0]

        self.port = port if port else randint(2000, 4000)
        self.username = username
        self.password = password

    def handle_client(self, connection):
        try:
            connection.settimeout(5)  # Set a timeout for the client connection

            # greeting header
            # read and unpack 2 bytes from a client
            version_data = connection.recv(2)
            if len(version_data) < 2:
                raise ValueError("Invalid version data")
            version, nmethods = version_data

            # get available methods [0, 1, 2]
            methods = self.get_available_methods(nmethods, connection)

            # accept only USERNAME/PASSWORD auth
            if 2 not in set(methods):
                # close connection
                connection.close()
                return

            # send welcome message
            connection.sendall(bytes([SOCKS_VERSION, 2]))

            if not self.verify_credentials(connection):
                return

            # request (version=5)
            request_data = connection.recv(4)
            if len(request_data) < 4:
                raise ValueError("Invalid request data")

            version, cmd, _, address_type = request_data

            if address_type == 1:  # IPv4
                address = socket.inet_ntoa(connection.recv(4))
            elif address_type == 3:  # Domain name
                domain_length_data = connection.recv(1)
                if len(domain_length_data) < 1:
                    raise ValueError("Invalid domain length data")
                domain_length = ord(domain_length_data)
                address = connection.recv(domain_length).decode('utf-8')
                address = socket.gethostbyname(address)

            # convert bytes to unsigned short array
            port_data = connection.recv(2)
            if len(port_data) < 2:
                raise ValueError("Invalid port data")
            port = int.from_bytes(port_data, 'big', signed=False)

            try:
                if cmd == 1:  # CONNECT
                    remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    # Set a timeout for the remote connection
                    remote.settimeout(5)
                    remote.connect((address, port))
                    bind_address = remote.getsockname()
                    print("* Connected to {} {}".format(address, port))
                else:
                    connection.close()

                addr = int.from_bytes(socket.inet_aton(
                    bind_address[0]), 'big', signed=False)
                port = bind_address[1]

                reply = b''.join([
                    SOCKS_VERSION.to_bytes(1, 'big'),
                    int(0).to_bytes(1, 'big'),
                    int(0).to_bytes(1, 'big'),
                    int(1).to_bytes(1, 'big'),
                    addr.to_bytes(4, 'big'),
                    port.to_bytes(2, 'big')
                ])
            except Exception as e:
                # return connection refused error
                reply = self.generate_failed_reply(address_type, 5)

            connection.sendall(reply)

            # establish data exchange
            if reply[1] == 0 and cmd == 1:
                self.exchange_loop(connection, remote)

            connection.close()

        except Exception as e:
            print("Error in handling client:", e)
            connection.close()

    def exchange_loop(self, client, remote):
        try:
            while True:
                # wait until client or remote is available for read
                r, w, e = select.select([client, remote], [], [], 5)

                if client in r:
                    data = client.recv(4096)
                    if not data:
                        break
                    if remote.send(data) <= 0:
                        break

                if remote in r:
                    data = remote.recv(4096)
                    if not data:
                        break
                    if client.send(data) <= 0:
                        break

        except Exception as e:
            print("Error in data exchange:", e)

        finally:
            client.close()
            remote.close()

    def generate_failed_reply(self, address_type, error_number):
        return b''.join([
            SOCKS_VERSION.to_bytes(1, 'big'),
            error_number.to_bytes(1, 'big'),
            int(0).to_bytes(1, 'big'),
            address_type.to_bytes(1, 'big'),
            int(0).to_bytes(4, 'big'),
            int(0).to_bytes(4, 'big')
        ])

    def verify_credentials(self, connection):
        try:
            version_data = connection.recv(1)
            if len(version_data) < 1:
                raise ValueError("Invalid version data")
            version = ord(version_data)  # should be 1

            username_len_data = connection.recv(1)
            if len(username_len_data) < 1:
                raise ValueError("Invalid username length data")
            username_len = ord(username_len_data)

            username = connection.recv(username_len).decode('utf-8')

            password_len_data = connection.recv(1)
            if len(password_len_data) < 1:
                raise ValueError("Invalid password length data")
            password_len = ord(password_len_data)

            password = connection.recv(password_len).decode('utf-8')

            if username == self.username and password == self.password:
                # success, status = 0
                response = bytes([version, 0])
                connection.sendall(response)
                return True

            # failure, status != 0
            response = bytes([version, 0xFF])
            connection.sendall(response)
            return False

        except Exception as e:
            print("Error in verifying credentials:", e)
            connection.close()
            return False

    def get_available_methods(self, nmethods, connection):
        methods = []
        for i in range(nmethods):
            methods.append(ord(connection.recv(1)))
        return methods

    def run(self, host, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((host, port))
        s.listen()

        print("* Socks5 proxy server is running on {}:{}".format(host, port))

        while True:
            conn, addr = s.accept()
            print("* new connection from {}".format(addr))
            t = threading.Thread(target=self.handle_client, args=(conn,))
            t.start()

    def return_proxy(self):
        result = {
            "host": self.host,
            "port": self.port,
            "username": self.username,
            "password": self.password
        }
        print(result)
        return result


def generate_proxy_config(proxy_type, host, port, username=None, password=None):
    """
    Generates a proxy configuration string based on the provided details.

    Args:
        proxy_type (str): Type of the proxy, e.g., 'socks5'.
        host (str): Proxy host or IP address.
        port (int): Proxy port.
        username (str, optional): Username for authenticated proxies. Defaults to None.
        password (str, optional): Password for authenticated proxies. Defaults to None.

    Returns:
        str: Proxy configuration string.
    """
    if proxy_type.lower() == 'socks5':
        if username and password:
            proxy_string = f"socks5://{username}:{password}@{host}:{port}"
        else:
            proxy_string = f"socks5://{host}:{port}"
    else:
        raise ValueError("Unsupported proxy type. Supported types: 'socks5'")

    return proxy_string


def run_proxy_server(username, password, port):
    proxy = Proxy(username, password, port)
    proxy_config = generate_proxy_config(
        "socks5", proxy.host, proxy.port, proxy.username, proxy.password)
    print("Proxy configuration:", proxy_config)
    proxy.run("0.0.0.0", proxy.port)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SOCKS5 Proxy Server")
    parser.add_argument("username", type=str, help="Proxy username")
    parser.add_argument("password", type=str, help="Proxy password")
    parser.add_argument("port", type=int, help="Proxy port")

    args = parser.parse_args()

    run_proxy_server(args.username, args.password, args.port)


# python proxy_server.py your_username your_password --port
