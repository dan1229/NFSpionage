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
					print_console("killing process on port " + str(port), trailing_dots=True)
					proc.send_signal(SIGTERM)
		if not found:
			print_console("no process found to kill on port " + str(port))
	except Exception as e:
		print_exception("KILLING process on port " + str(port) + "\n" + str(e))


# print_exception ====================================== #
# default printing for exceptions
def print_exception(s, tag="EXP", sym="-"):
	print_console(s, tag=tag, sym=sym)


# print_console ========================================= #
# default console printing
def print_console(s, tag="INF", sym="*", trailing_dots=False):
	s = "[" + str(sym) + " " + str(tag) + "] " + str(s)
	if trailing_dots:
		s += "..."
	print(s)
