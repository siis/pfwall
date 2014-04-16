from struct import * 
import ctypes
import getopt
import pft_c
import pdb 

MAX_STRLEN = 256
PFT_NAMELEN = 16
PF_STATE_STR_MAX = 128

PF_VALUE_GIVEN = 0
PF_VALUE_FROM_CONTEXT = 1

class test_value_union(ctypes.Union):
	_fields_ = 	[
			("value_str", ctypes.c_char * PF_STATE_STR_MAX),
			("value_context", ctypes.c_int)
			]

class pft_state_match(ctypes.Structure):
	_fields_ = 	[
			("match_size", ctypes.c_uint),
			("name", ctypes.c_char * PFT_NAMELEN),
			("context_mask", ctypes.c_uint),
			("match", ctypes.c_void_p),
			("key", ctypes.c_char * PF_STATE_STR_MAX),
			("value_origin", ctypes.c_int),
			("test_value", test_value_union),
			("equal", ctypes.c_int),
			("uninit", ctypes.c_int)
			]

""" --key --compare --(n)equal """

# argv is of the form --string "tomatch"
def match_prepare(argv):

	equal = 1
	key = ""
	test_value = ""
	uninit = 0
	value_origin = PF_VALUE_GIVEN

	optlist, args = getopt.getopt(argv, "enk:c:u")
	for o, a in optlist:
		if o == "-e":
			equal = 1
		elif o == "-n":
			equal = 0
		elif o == "-k":
			key = a
		elif o == "-u": # Check for existence of key, match if unset
			uninit = 1
		elif o == "-c":
			if a == "PF_CONTEXT_FILENAME":
				value_origin = PF_VALUE_FROM_CONTEXT
				test_value = pft_c.PF_CONTEXT_FILENAME
			else:
				value_origin = PF_VALUE_GIVEN
				test_value = a
	
	pft_match_entry = pft_state_match()
	pft_match_entry.match_size = ctypes.sizeof(pft_state_match)
	pft_match_entry.name = "state"
	if value_origin == PF_VALUE_FROM_CONTEXT:
		pft_match_entry.context_mask = test_value
	else:
		pft_match_entry.context_mask = 0
	pft_match_entry.key = key
	pft_match_entry.value_origin = value_origin
	if value_origin == PF_VALUE_FROM_CONTEXT:
		pft_match_entry.test_value.value_context = test_value
	else:
		pft_match_entry.test_value.value_str = test_value
	pft_match_entry.equal = equal
	pft_match_entry.uninit = uninit

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
