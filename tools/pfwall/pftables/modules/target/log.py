from struct import *
import ctypes
import pft_c
import getopt

MAX_STRLEN = 256
PFT_NAMELEN = 16

PF_SYSCALL_STRING = 1
PF_SYSCALL_INT = 2

class pft_target_log(ctypes.Structure):
	_fields_ = 	[
			("target_size", ctypes.c_uint),
			("name", ctypes.c_char * PFT_NAMELEN),
			("context_mask", ctypes.c_uint),
			("target", ctypes.c_void_p),
			("context", ctypes.c_uint), # Repeat of context mask
			("string", ctypes.c_char * MAX_STRLEN),
			("arg_num", ctypes.c_uint),
			("offset", ctypes.c_uint),
			("type", ctypes.c_uint)
			]

# Return a byte array
# argv is of the form --message "tag" (this will be logged along with the packet)
# It is possible that there is no message, in this case, just log

def target_prepare(argv):
	pft_target_entry = pft_target_log()
	pft_target_entry.target_size = ctypes.sizeof(pft_target_entry)
	pft_target_entry.name = "log"
	pft_target_entry.context_mask = pft_c.PF_CONTEXT_TYPE | pft_c.PF_CONTEXT_INTERFACE | \
				pft_c.PF_CONTEXT_VM_AREA_STRINGS | pft_c.PF_CONTEXT_BINARY_PATH | \
				pft_c.PF_CONTEXT_FILENAME
 	pft_target_entry.string = ""
	i = 0
	optlist, args = getopt.getopt(argv, "s:c:a:o:t:")

	for o, a in optlist:
		if o == "-s":
			pft_target_entry.string = a
		if o == "-c":
			if "PF_CONTEXT_DATA" in a: 
				pft_target_entry.context_mask |= pft_c.PF_CONTEXT_DATA
				pft_target_entry.context |= pft_c.PF_CONTEXT_DATA
			if "PF_CONTEXT_INTERFACE" in a:
				pft_target_entry.context_mask |= pft_c.PF_CONTEXT_INTERFACE
				pft_target_entry.context |= pft_c.PF_CONTEXT_INTERFACE
			if "PF_CONTEXT_SYSCALL_ARGS" in a:
				pft_target_entry.context_mask |= pft_c.PF_CONTEXT_SYSCALL_ARGS
				pft_target_entry.context |= pft_c.PF_CONTEXT_SYSCALL_ARGS
			if "PF_CONTEXT_SYSCALL_FILENAME" in a:
				pft_target_entry.context_mask |= pft_c.PF_CONTEXT_SYSCALL_FILENAME
				pft_target_entry.context |= pft_c.PF_CONTEXT_SYSCALL_FILENAME
			if "PF_CONTEXT_STATE" in a:
				pft_target_entry.context_mask |= pft_c.PF_STATE
				pft_target_entry.context |= pft_c.PF_STATE
			if "PF_CONTEXT_FILENAME" in a:
				pft_target_entry.context_mask |= pft_c.PF_CONTEXT_FILENAME
				pft_target_entry.context |= pft_c.PF_CONTEXT_FILENAME
		# SYSCALL_ARGS-specific parsing
		if o == "-a":
			pft_target_entry.arg_num = int(a)
		if o == "-o":
			pft_target_entry.offset = int(a)
		if o == "-t":
			if a.lower() == "int":
				pft_target_entry.type = PF_SYSCALL_INT
			elif a.lower() == "string":
				pft_target_entry.type = PF_SYSCALL_STRING
		
	return pft_target_entry

	"""
	bytelist = pack('IsIPs', 
				pft_target_entry.target_size,
				pft_target_entry.name,
				pft_target_entry.context_mask,
				0,
				pft_target_entry.string
			)
	return bytelist
	"""
