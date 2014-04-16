from struct import * 
import ctypes
import getopt

MAX_STRLEN = 256
PFT_NAMELEN = 16
PF_STATE_STR_MAX = 128

PF_SYSCALL_STRING = 1
PF_SYSCALL_INT = 2

class test_value_union(ctypes.Union):
	_fields_ = 	[
			("test_value_int", ctypes.c_int),
			("test_value_str", ctypes.c_char * PF_STATE_STR_MAX)
			]

class pft_syscall_match(ctypes.Structure):
	_fields_ = 	[
			("match_size", ctypes.c_uint),
			("name", ctypes.c_char * PFT_NAMELEN),
			("context_mask", ctypes.c_uint),
			("match", ctypes.c_void_p),
			("arg_num", ctypes.c_int), # nth argument (0 - syscall #)
			("offset", ctypes.c_int), 
			("type", ctypes.c_int), 
			("equal", ctypes.c_int),
			("v", test_value_union)
			]

""" --arg --offset  --type INT/STRING --(n)equal --compare """

def match_prepare(argv):

	equal = 0
	arg_num = 0
	offset = 0
	val_type = 0
	test_value = ""

	optlist, args = getopt.getopt(argv, "a:o:t:c:en")
	for o, a in optlist:
		if o == "-a":
			arg_num = int(a)
		elif o == "-n":
			equal = 0
		elif o == "-e":
			equal = 1
		elif o == "-o":
			offset = int(a)
		elif o == "-t":
			if a.lower() == "int":
				val_type = PF_SYSCALL_INT
			elif a.lower() == "string":
				val_type = PF_SYSCALL_STRING
		elif o == "-c":
			test_value = a

	pft_match_entry = pft_syscall_match()
	pft_match_entry.match_size = ctypes.sizeof(pft_syscall_match)
	pft_match_entry.name = "syscall"
	pft_match_entry.context_mask = 0 # No context needed
	pft_match_entry.arg_num = arg_num
	pft_match_entry.offset = offset
	pft_match_entry.type = val_type
	pft_match_entry.equal = equal
	if val_type == PF_SYSCALL_INT:
		pft_match_entry.v.test_value_int = int(test_value)
	elif val_type == PF_SYSCALL_STRING:
		pft_match_entry.v.test_value_str = test_value
	
	return pft_match_entry

	"""
	bytelist = pack('IsIps', 
				pft_match_entry.match_size,
				pft_match_entry.name,
				pft_match_entry.context_mask,
				0,
				pft_match_entry.string
		       )
	return bytelis
	"""
