from datetime import datetime

from scapy.layers.inet import IP
from scapy.sendrecv import sniff


def forward_packet(packet):
	now = datetime.now()
	print("\t" + str(now) + "\n")
	print("\tSRC: " + str(packet[IP].src) + "\n")
	print("\tDST: " + str(packet[IP].dst) + "\n")


def network_listen(ip_addr, port):
	filter = "tcp"
	print("FILTER: \'" + str(filter) + "\'")
	while True:
		packets = sniff(count=1, filter=filter)
		print("=============================================")
		print("packet: " + str(packets))
		forward_packet(packets.res[0])


if __name__ == '__main__':
	import optparse

	parser = optparse.OptionParser()

	parser.add_option(
		'-s', '--server-ip', dest='server_ip',
		help='NFS server IP address to bind to')
	parser.add_option(
		'-p', '--server-port', dest='server_port',
		help='NFS server port address to bind to')

	options, args = parser.parse_args()

	network_listen(options.server_ip, options.server_port)
