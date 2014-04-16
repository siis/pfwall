from struct import *
import ctypes
import getopt
import pft_c

MAX_STRLEN = 256
PFT_NAMELEN = 16
class pft_target_symlink(ctypes.Structure):
	_fields_ = 	[
			("target_size", ctypes.c_uint),
			("name", ctypes.c_char * PFT_NAMELEN),
			("context_mask", ctypes.c_uint),
			("target", ctypes.c_void_p),
			("flags", ctypes.c_uint),
			("check_find", ctypes.c_uint)
			]

SYMLINK = 0x1
HARDLINK = 0x2
SQUAT = 0x4

# Return a byte array
# argv is of the form --message "tag" (this will be logged along with the packet)
# It is possible that there is no message, in this case, just log

def target_prepare(argv):
	flags = 0
	check_find = 0
	optlist, args = getopt.getopt(argv, "f:c")
	for o, a in optlist:
		if o == "-f":
			if a == "SYMLINK":
				flags |= SYMLINK
			elif a == "HARDLINK":
				flags |= HARDLINK
			elif a == "SQUAT":
				flags |= SQUAT
		if o == "-c":
			check_find = 1
	pft_target_entry = pft_target_symlink()
	pft_target_entry.target_size = ctypes.sizeof(pft_target_entry)
	pft_target_entry.name = "fuzz_resource"
	pft_target_entry.context_mask = pft_c.PF_CONTEXT_SYSCALL_FILENAME
	pft_target_entry.flags = flags
	pft_target_entry.check_find = check_find 

	return pft_target_entry
