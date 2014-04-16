from struct import *
import ctypes

MAX_STRLEN = 256
PFT_NAMELEN = 16
class pft_target_syscall_invoked(ctypes.Structure):
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
	pft_target_entry = pft_target_syscall_invoked()
	pft_target_entry.target_size = ctypes.sizeof(pft_target_entry)
	pft_target_entry.name = "syscall_invoked"
	pft_target_entry.context_mask = 0 # No context needed
	return pft_target_entry
