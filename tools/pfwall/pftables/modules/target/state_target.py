from struct import *
import ctypes
import pft_c
import getopt 
import pdb 

MAX_STRLEN = 256
PFT_NAMELEN = 16
PF_STATE_STR_MAX = 128

PF_STATE_SET = 1
PF_STATE_REMOVE = 2

PF_STATE_NONE = 0
PF_STATE_ADD = 1
PF_STATE_SUBTRACT = 2

PF_VALUE_GIVEN = 0
PF_VALUE_FROM_CONTEXT = 1

class value_union(ctypes.Union):
	_fields_ = 	[
			("value_str", ctypes.c_char * PF_STATE_STR_MAX),
			("value_context", ctypes.c_int)
			]

class pft_target_state(ctypes.Structure):
	_fields_ = 	[
			("target_size", ctypes.c_uint),
			("name", ctypes.c_char * PFT_NAMELEN),
			("context_mask", ctypes.c_uint),
			("target", ctypes.c_void_p),
			("key", ctypes.c_char * PF_STATE_STR_MAX),
			("value_origin", ctypes.c_int),
			("value", value_union),
			("add", ctypes.c_int),
			("flags", ctypes.c_int),
			("decision", ctypes.c_int)
			]

# Return a byte array
# argv is of the form --message "tag" (this will be logged along with the packet)
# It is possible that there is no message, in this case, just log

""" --set --key --value val --accept/--drop
	--remove --key --accept/--drop
    --set --key --value val --add(-i)/--subtract(-n) --accept/--drop
"""


def target_prepare(argv):
	action = 0 # set/remove
	key = ""
	value = ""
	decision = pft_c.PF_CONTINUE # accept/drop
	add = PF_STATE_NONE
	value_origin = PF_VALUE_GIVEN

	optlist, args = getopt.getopt(argv, "srk:v:adin")
	for o, a in optlist:
		if o == "-s":
			action = PF_STATE_SET
		elif o == "-k":
			key = a
		elif o == "-v":
			if a == "PF_CONTEXT_FILENAME": # TODO: Should change it to PF_CONTEXT_INODE
				value_origin = PF_VALUE_FROM_CONTEXT
				value = pft_c.PF_CONTEXT_FILENAME
			else:
				value_origin = PF_VALUE_GIVEN
				value = a
		elif o == "-r":
			action = PF_STATE_REMOVE
		elif o == "-a":
			decision = pft_c.PF_ACCEPT
		elif o == "-d":
			decision = pft_c.PF_DROP
		elif o == "-i":
			add = PF_STATE_ADD
		elif o == "-n":
			add = PF_STATE_SUBTRACT
	
	pft_target_entry = pft_target_state()
	pft_target_entry.target_size = ctypes.sizeof(pft_target_state)
	pft_target_entry.name = "state"
	if value_origin == PF_VALUE_FROM_CONTEXT:
		pft_target_entry.context_mask = value
	else:
		pft_target_entry.context_mask = 0
	pft_target_entry.key = key
	pft_target_entry.value_origin = value_origin
	if value_origin == PF_VALUE_FROM_CONTEXT:
		pft_target_entry.value.value_context = value
	else:
		pft_target_entry.value.value_str = str(value)
	pft_target_entry.add = add
	pft_target_entry.flags = action
	pft_target_entry.decision = decision

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
