import _thread
from _signal import SIGTERM
from datetime import datetime

from psutil import process_iter

from port_forwarder import MitmForwarder

PORT_RPC = 111
PORT_NFS = 2049


# kills process on specified port number
def kill_process_on_port(port):
	found = False
	try:
		for proc in process_iter():
			for conns in proc.connections(kind='inet'):
				if conns.laddr.port == port:
					found = True
					print("[* INF ] killing process on port " + str(port))
					proc.send_signal(SIGTERM)
		if not found:
			print("[* INF ] no process found to kill on port " + str(port))
	except Exception as e:
		print("[* EXP ] exception while trying to kill process on port " + str(port) + "\n" + str(e))


def run(ip_nfs_server):
	print("// ========================================================================")
	print("Starting NFS MITM @ " + str(datetime.now()) + "\n")
	print("SERVER IP:\t\t" + ip_nfs_server)
	print("NFS PORT:\t\t" + str(PORT_NFS))
	print("")

	# kill processes on either port just in case
	kill_process_on_port(PORT_NFS)
	kill_process_on_port(PORT_RPC)

	# start forwarders for NFS and RPC (Remote Procedure Call) for TCP and UDP
	_thread.start_new_thread(MitmForwarder, (ip_nfs_server, PORT_NFS, False))
	_thread.start_new_thread(MitmForwarder, (ip_nfs_server, PORT_NFS, True))
	# _thread.start_new_thread(MitmForwarder, (ip_nfs_server, PORT_RPC, False))
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
