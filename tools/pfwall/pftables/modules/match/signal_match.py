from struct import * 
import ctypes
import getopt

MAX_STRLEN = 256
PFT_NAMELEN = 16

class pft_signal_match(ctypes.Structure):
	_fields_ = 	[
			("match_size", ctypes.c_uint),
			("name", ctypes.c_char * PFT_NAMELEN),
			("context_mask", ctypes.c_uint),
			("match", ctypes.c_void_p),
			]

""" --key --compare --(n)equal """

# argv is of the form --string "tomatch"
def match_prepare(argv):

	pft_match_entry = pft_signal_match()
	pft_match_entry.match_size = ctypes.sizeof(pft_signal_match)
	pft_match_entry.name = "signal"
	pft_match_entry.context_mask = 0 # No context needed

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
