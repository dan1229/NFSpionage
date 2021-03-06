import socket


# API to distribute connection credentials to clients
# connect to localhost:2050
# see text_client.py for example on basic connection and usage


class NfsMitmApi:
    nfs_context = None
    port = 2050

    def __init__(self, nfs_server_ip, mount_path):
        if mount_path[0] != '/':
            mount_path = '/' + mount_path
            
        self.mount_url = 'nfs://' + nfs_server_ip + mount_path

        print("// ========================================")
        print("// Starting NFS MITM API...")
        print("// [*] IP ADDR:\t\tlocalhost:" + str(self.port))
        print("// [*] MNT URL:\t\t" + self.mount_url)
        print("// ========================================")

        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind(('', self.port))
        server_socket.listen(5)

        # listen for requests on localhost:2050
        while True:
            client_socket, client_address = server_socket.accept()
            print("[* API ] sending mount url (" + self.mount_url + ") to " + str(client_address))
            client_socket.send(self.mount_url.encode())
