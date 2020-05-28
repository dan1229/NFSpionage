from datetime import datetime

from scapy.sendrecv import sniff


def forward_packet(packet):
	now = datetime.now()
	print("\t" + str(now) + " packet: " + str(packet))


def network_listen(ip_addr, port):
	scapy_filter = "port 80"
	print("FILTER: " + scapy_filter)
	while True:
		print("listening...")
		packet = sniff(count=1)
		print("\tpacket: " + str(packet))


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
