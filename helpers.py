from _signal import SIGTERM

from psutil import process_iter

PORT_RPC = 111
PORT_NFS = 2049

'''
# ==============================================================================
# HELPERS ======================================================================
# ==============================================================================
'''


# kill_process_on_port =================================== #
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


# print_exception ====================================== #
# default printing for exceptions
def print_exception(s, tag="EXP", sym="-"):
	print_console(s, tag=tag, sym=sym)


# print_console ========================================= #
# default console printing
def print_console(s, tag="INF", sym="*"):
	print("[" + str(sym) + " " + str(tag) + "] " + str(s))
