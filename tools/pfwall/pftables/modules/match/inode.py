from struct import * 
import ctypes
import pft_c
import getopt 

MAX_STRLEN = 256
PFT_NAMELEN = 16

class pft_match_inode_match(ctypes.Structure):
	_fields_ = 	[
			("match_size", ctypes.c_uint),
			("name", ctypes.c_char * PFT_NAMELEN),
			("context_mask", ctypes.c_uint),
			("match", ctypes.c_void_p),
			("inode_number", ctypes.c_ulong), 
			]

# argv is of the form --inode "tomatch"
def match_prepare(argv):
	pft_match_entry = pft_match_inode_match()
	pft_match_entry.match_size = ctypes.sizeof(pft_match_entry)
	pft_match_entry.name = "inode"
	pft_match_entry.context_mask = pft_c.PF_CONTEXT_FILENAME
	pft_match_entry.inode_number = 0

	optlist, args = getopt.getopt(argv, "n:")
	for o, a in optlist:
		if o == "-n": 
			pft_match_entry.inode_number = int(a)

	return pft_match_entry
	"""
	bytelist = pack('IsIps', 
				pft_match_entry.match_size,
				pft_match_entry.name,
				pft_match_entry.context_mask,
				0,
				pft_match_entry.inode
		       )
	return bytelis
	"""
