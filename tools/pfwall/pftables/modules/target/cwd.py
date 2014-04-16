from struct import *
import ctypes
import pft_c
import getopt 
import pdb 

MAX_STRLEN = 256
PFT_NAMELEN = 16
class pft_target_cwd(ctypes.Structure):
	_fields_ = 	[
			("target_size", ctypes.c_uint),
			("name", ctypes.c_char * PFT_NAMELEN),
			("context_mask", ctypes.c_uint),
			("target", ctypes.c_void_p),
			]

def target_prepare(argv):
	pft_target_entry = pft_target_cwd()
	pft_target_entry.target_size = ctypes.sizeof(pft_target_cwd)
	pft_target_entry.name = "cwd"
	pft_target_entry.context_mask = 0
	return pft_target_entry
