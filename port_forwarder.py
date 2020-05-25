import _thread
import socket
import threading


from nfs_mitm_api import NfsMitmApi
from scapy.scapy.compat import raw
from scapy.scapy.contrib.mount import MOUNT_Call
from scapy.scapy.contrib.oncrpc import RPC
from scapy.scapy.supersocket import SuperSocket


def tuple_to_addr(address):
    return str(address[0]) + ":" + str(address[1])


def handle(buffer):
    return buffer


class MitmForwarder:
    mount_ports = []
    spoof_address = None

    def __init__(self, remote_ip, port, udp=False):
        print("// ========================================")
        print("// Starting MitmForwarder...")
        print("// [*] LOC Addr:\t127.0.0.1:" + str(port))
        print("// [*] REM Addr:\t" + remote_ip + ":" + str(port))
        if udp:
            print("// [*] PROT:\t\tUDP")
            self.udp_proxy(remote_ip, port)
        else:
            print("// [*] PROT:\t\tTCP")
            self.tcp_proxy(remote_ip, port)
        print("// ========================================")

    def update_spoof_address(self, addr):
        if self.spoof_address is None or self.spoof_address is '127.0.0.1' or self.spoof_address is '0.0.0.0' or self.spoof_address is '':
            self.spoof_address = addr

    # ==================== TCP FORWARDING ==================== #

    # create tcp servers to listen for and forward connections to target
    def tcp_proxy(self, target_host, target_port):
        SuperSocket()
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(('', target_port))
        server_socket.listen(10)

        while True:
            # accept connection from client
            local_socket, local_address = server_socket.accept()
            self.update_spoof_address(local_address[0])

            # create socket to connect to server
            remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote_socket.bind(('', local_address[1]))
            remote_socket.connect((target_host, target_port))

            # create threads for each direction
            s = threading.Thread(target=self.transfer_tcp, args=(remote_socket, local_socket))
            r = threading.Thread(target=self.transfer_tcp, args=(local_socket, remote_socket))
            s.start()
            r.start()

    # listens for tcp connections and forwards data from src socket to dst socket
    def transfer_tcp(self, src, dst):
        while True:
            data = src.recv(64512)
            print("[+ TCP ] " + tuple_to_addr(src.getpeername()) + " >>> " + tuple_to_addr(dst.getpeername()) + " [" + str(len(data)) + "]")
            dst.send(handle(data))

    # ==================== UDP FORWARDING ==================== #

    # create udp servers to listen for and forward connections to target
    def udp_proxy(self, remote_ip, listen_port):
        proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        proxy_socket.bind(('', listen_port))

        server_address = (remote_ip, int(listen_port))
        client_address = None

        while True:
            data, address = proxy_socket.recvfrom(65412)
            self.filter_packets(data, remote_ip, client_address, server_address)

            #  create spoof socket to send packets from
            spoof_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            spoof_socket.bind(('', address[1]))

            if client_address is None:
                client_address = address
            # client addr, send to server (listen on spoof socket for resp)
            if address == client_address:
                print(
                    "[+ UDP ] " + tuple_to_addr(client_address) + " >>> " + tuple_to_addr(server_address) + " [" + str(
                        len(data)) + "]")
                spoof_socket.sendto(data, server_address)
                self.udp_listen(spoof_socket, proxy_socket)
            # server addr, send to client
            elif address == server_address:
                print(
                    "[+ UDP ] " + tuple_to_addr(server_address) + " >>> " + tuple_to_addr(client_address) + " [" + str(
                        len(data)) + "]")
                proxy_socket.sendto(data, client_address)
                client_address = None
            # unknown addr, send to server
            else:
                print(
                    "[+ UDP ] " + tuple_to_addr(server_address) + " >>> " + tuple_to_addr(client_address) + " [" + str(
                        len(data)) + "]")
                proxy_socket.sendto(data, client_address)
                client_address = None

    @staticmethod
    def udp_listen(src, dst):
        data, address = src.recvfrom(65412)
        src.sendto(data, dst.getsockname())

    # ==================== PACKET FILTERING ==================== #

    # filter packets for data of interest - i.e., mount port and mount path
    def filter_packets(self, data, remote_ip, client_address, server_address):
        port = self.filter_mount_port(data)
        if port != -1 and port not in self.mount_ports and client_address is not server_address:
            print("[* INF ] starting forwarders on port " + str(port))
            _thread.start_new_thread(MitmForwarder, (remote_ip, port))
            _thread.start_new_thread(MitmForwarder, (remote_ip, port, True))
            self.mount_ports.append(port)

        # filter path, start mitm API
        path = self.filter_mount_path(data)
        if path != -1:
            print("[* INF ] starting NFS MITM API on path \'" + path + "\'")
            _thread.start_new_thread(NfsMitmApi, (remote_ip, path))

    @staticmethod
    def filter_mount_port(data):
        try:  # get port number from last few bytes
            sz = len(data)
            x = data[sz - 2:sz]
            tmp = x.hex()
            port = int(tmp, 16)

            if port != 0 and port > 100:
                print("[* INF ] MOUNT on port " + str(port))
                return port
            else:
                return -1
        except Exception as e:  # error getting mount port
            # str("[- EXP ] " + str(e))
            return -1

    @staticmethod
    def filter_mount_path(data):
        try:  # try to convert to MOUNT_Call packet
            mnt_pckt = RPC(MOUNT_Call(raw(data)))
            path = mnt_pckt.path.path.decode('utf-8')
            print("[* INF ] MOUNT on path " + path)
            return path
        except Exception as e:  # error getting mount path
            # print("[- EXP ] " + str(e))
            return -1

