from struct import * 
import ctypes
import pft_c
import getopt

MAX_STRLEN = 256
PFT_NAMELEN = 16

ATTACKER_BIND = 0x100
ATTACKER_PREBIND = 0x80

class pft_permission_match(ctypes.Structure):
	_fields_ = 	[
			("match_size", ctypes.c_uint),
			("name", ctypes.c_char * PFT_NAMELEN),
			("context_mask", ctypes.c_uint),
			("match", ctypes.c_void_p),
			("flags", ctypes.c_uint),
			]

# argv is of the form -p flags
def match_prepare(argv):
	pft_match_entry = pft_permission_match()
	pft_match_entry.match_size = ctypes.sizeof(pft_match_entry)
	pft_match_entry.name = "permission"
	pft_match_entry.context_mask = pft_c.PF_CONTEXT_SYSCALL_FILENAME
	pft_match_entry.flags = 0

	optlist, args = getopt.getopt(argv, "p:")
	for o, a in optlist:
		if o == "-p":
			if "ATTACKER_BIND" in a:
				pft_match_entry.flags |= ATTACKER_BIND
			if "ATTACKER_PREBIND" in a:
				pft_match_entry.flags |= ATTACKER_PREBIND

	return pft_match_entry
