from struct import * 
import ctypes
import getopt
import pft_c

MAX_STRLEN = 256
PFT_NAMELEN = 16

class pft_attacker_marked_match(ctypes.Structure):
	_fields_ = 	[
			("match_size", ctypes.c_uint),
			("name", ctypes.c_char * PFT_NAMELEN),
			("context_mask", ctypes.c_uint),
			("match", ctypes.c_void_p),
			]

""" No arguments """

# argv is of the form --string "tomatch"
def match_prepare(argv):

	pft_match_entry = pft_attacker_marked_match()
	pft_match_entry.match_size = ctypes.sizeof(pft_attacker_marked_match)
	pft_match_entry.name = "attacker_marked"
	pft_match_entry.context_mask = pft_c.PF_CONTEXT_SYSCALL_FILENAME 

	return pft_match_entry
