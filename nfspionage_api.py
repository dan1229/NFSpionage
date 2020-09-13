import socket

from helpers import print_console

'''
# ==============================================================================
# NFSPIONAGE API ===============================================================
# ==============================================================================
'''


# a simple TCP/Socket based API to distribute connection credentials to clients
# simply connect to localhost:2050 while NFS connection is being mitm'ed to get
# relevant mount info - namely the mount path
#
# see text_client.py for example on basic connection and usage

class NfspionageApi:
    nfs_context = None
    port = 2050

    def __init__(self, nfs_server_ip, mount_path):
        if mount_path[0] != '/':
            mount_path = '/' + mount_path

        self.mount_url = 'nfs://' + nfs_server_ip + mount_path

        print_console("// ========================================")
        print_console("// Starting NFS MITM API", trailing_dots=True)
        print_console("// [*] IP ADDR:\t\tlocalhost:" + str(self.port))
        print_console("// [*] MNT URL:\t\t" + self.mount_url)
        print_console("// ========================================")

        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind(('', self.port))
        server_socket.listen(5)

        # listen for requests on localhost:2050
        while True:
            client_socket, client_address = server_socket.accept()
            print_console("sending mount url (" + self.mount_url + ") to " + str(client_address), tag="API")
            client_socket.send(self.mount_url.encode())
