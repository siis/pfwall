from struct import *
import ctypes

MAX_STRLEN = 256
PFT_NAMELEN = 16
class pft_target_deny(ctypes.Structure):
	_fields_ = 	[
			("target_size", ctypes.c_uint),
			("name", ctypes.c_char * PFT_NAMELEN),
			("context_mask", ctypes.c_uint),
			("target", ctypes.c_void_p),
			]

# Return a byte array
# argv is of the form --message "tag" (this will be logged along with the packet)
# It is possible that there is no message, in this case, just log

def target_prepare(argv):
	pft_target_entry = pft_target_deny()
	pft_target_entry.target_size = ctypes.sizeof(pft_target_entry)
	pft_target_entry.name = "drop"
	pft_target_entry.context_mask = 0 # No context needed
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
