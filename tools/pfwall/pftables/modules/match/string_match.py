from struct import * 
import ctypes

MAX_STRLEN = 256
PFT_NAMELEN = 16

class pft_match_string_match(ctypes.Structure):
	_fields_ = 	[
			("match_size", ctypes.c_uint),
			("name", ctypes.c_char * PFT_NAMELEN),
			("context_mask", ctypes.c_uint),
			("match", ctypes.c_void_p),
			("string", ctypes.c_char * MAX_STRLEN)
			]

# argv is of the form --string "tomatch"
def match_prepare(argv):
	pft_match_entry = pft_match_string_match()
	pft_match_entry.match_size = ctypes.sizeof(pft_match_entry)
	pft_match_entry.name = "string_match"
	pft_match_entry.context_mask = pft_c.PF_CONTEXT_DATA
	pft_match_entry.string = argv[1] 

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
