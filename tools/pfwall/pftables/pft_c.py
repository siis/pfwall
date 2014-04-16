import ctypes
import sys

PATH_MAX = 4096
PFT_NAMELEN = 16
PF_MAX_CHAINS = 32 # Max number of chains allowed in a table


PF_CONTEXT_DATA = 0x1
PF_CONTEXT_SIGNAL = 0x2
PF_CONTEXT_SYSCALL_ARGS = 0x4
PF_CONTEXT_STATE = 0x8
PF_CONTEXT_INTERFACE = 0x10
PF_CONTEXT_FILENAME = 0x20
PF_CONTEXT_VM_AREA_STRINGS = 0x40
PF_CONTEXT_TYPE = 0x80
PF_CONTEXT_TYPE_SID = 0x100
PF_CONTEXT_BINARY_PATH = 0x200
PF_CONTEXT_BINARY_PATH_INODE = 0x400
PF_CONTEXT_SIGINFO = 0x800
PF_CONTEXT_SYSCALL_FILENAME = 0x1000
PF_CONTEXT_DAC_BINDERS = 0x2000
PF_CONTEXT_RESOURCE = 0x4000

PF_NON_DEFAULT_HOOK = -1 # user-defined chains
PF_NR_HOOKS = 7 # For now, avc_has_perm, inode post create, and read(). 
PF_HOOK_INPUT = 0
PF_HOOK_OUTPUT = 1
PF_HOOK_READ = 2
PF_HOOK_CREATE = 3
PF_HOOK_SYSCALL_BEGIN = 4
PF_HOOK_SYSCALL_RETURN = 5
PF_HOOK_SIGNAL_DELIVER = 6

PF_ACCEPT = 0x1
PF_DROP = 0x0
PF_CONTINUE = 0x2
PF_RETURN = 0x4

# Skip-hook optimization
#TODO: This is an artificial limit so a size can be agreed upon between kernel and userspace for pft_table. 
PF_MAX_LSM_HOOKS = 32

default_table = "filter"

# TODO: Why is default_chains_dict[i] != default_chains[i]? Why does program generate error if you use default_chains_dict?
default_chains = ["input", "output", "read", "create", "syscallbegin", "syscallend", "signaldelivery"]

default_chains_dict = {	
		PF_HOOK_INPUT	:	"input",
		PF_HOOK_OUTPUT	:	"output",
		PF_HOOK_READ	:	"read",
		PF_HOOK_CREATE	:	"create",
		PF_HOOK_SYSCALL_BEGIN	:	"syscallbegin",
		PF_HOOK_SYSCALL_RETURN	:	"syscallend",
		PF_HOOK_SIGNAL_DELIVER	:	"signaldelivery",
		}

default_chains_inv = dict((default_chains_dict[k], k) for k in default_chains_dict)
# 0 or None (NULL) for don't cares
class pft_default_matches(ctypes.Structure):
	_fields_ = 	[
			("interface", ctypes.c_ulong), 
			("script_path", ctypes.c_char * PATH_MAX),
			("script_inoden", ctypes.c_ulong), # Ignore
			("script_line_number", ctypes.c_ulong),
			("binary_path", ctypes.c_char * PATH_MAX),
			("binary_inoden", ctypes.c_ulong), # Ignore
			("vm_area_name", ctypes.c_char * PATH_MAX),
			("vm_area_inoden", ctypes.c_ulong), # Ignore
			("process_label", ctypes.c_char * 256),
			("ssid", ctypes.c_uint * 2), # Ignore
			("object_label", ctypes.c_char * 256),
			("tsid", ctypes.c_uint * 2), # Ignore
			("tclass", ctypes.c_ushort),
			("requested", ctypes.c_uint)
			]

# The last fields of the following structures have to be ignored, and the data just concatenated. 
# Note that we could fill in next, jump_offset ourselves like iptables does, but this would work
# only for sequential traversal. Hence, we let the kernel do all the work, be it for sequential 
# or hashing traversal. 
class pft_entry(ctypes.Structure):
	_fields_ = 	[
			("id", ctypes.c_uint),
			("class", ctypes.c_uint), # Ignore
			("def", pft_default_matches),
			("target_offset", ctypes.c_uint), 
			("next_offset", ctypes.c_uint), 
			("jump_offset", ctypes.c_uint), # Ignore
			("counter", ctypes.c_uint) # Init to 0
#			("beg_mat_tar", ctypes.c_char)
			]

class pft_match(ctypes.Structure):
	_fields_ = 	[
			("match_size", ctypes.c_uint),
			("name", ctypes.c_char * PFT_NAMELEN),
			("context_mask", ctypes.c_uint),
			("match", ctypes.c_void_p) # Ignore
#			("match_specific", ctypes.c_char)
			]

class pft_target(ctypes.Structure):
	_fields_ = 	[
			("target_size", ctypes.c_uint),
			("name", ctypes.c_char * PFT_NAMELEN),
			("context_mask", ctypes.c_uint),
			("target", ctypes.c_void_p) # Ignore
#			("target_specific", ctypes.c_char)
			]

class pft_chain(ctypes.Structure):
	_fields_ = 	[
			("name", ctypes.c_char * PFT_NAMELEN),
			("chain_offset", ctypes.c_uint)
			]

class pft_lsm_hook(ctypes.Structure):
	_fields_ = 	[
			("tclass", ctypes.c_ushort),
			("requested", ctypes.c_uint)
			]

class pft_table(ctypes.Structure): # Actually, pft_table
	_fields_ = 	[
			("initialized", ctypes.c_int), # Ignore
			("name", ctypes.c_char * PFT_NAMELEN),
			("size", ctypes.c_int), 
			# The below two fields are for skip-hook optimization
			("hooks_enabled", ctypes.c_uint * PF_NR_HOOKS), # The hooks on which this table has rules (does not differentiate within LSM hooks)
			("lsm_hooks_enabled", pft_lsm_hook * PF_MAX_LSM_HOOKS), # The LSM hooks (tclass, requested) (TODO: artificial limit on the number of hooks that can have rules). 
			("hook_entries", ctypes.c_uint * PF_NR_HOOKS), # As offsets from table_base
			# We need information about chains in pfwall to setup hashing traversal
			("num_chains", ctypes.c_int), 
			("chains", pft_chain * PF_MAX_CHAINS), 
			("stackptr", ctypes.c_void_p), # Ignore
			("jumpstack", ctypes.c_char_p), # Ignore
			("table_base", ctypes.c_char_p), # Ignore 
			]

# Helper functions to create various structures above

def create_pft_default_matches(interface, script_filename, script_line_number, binary_path, vm_area_name,
		process_label, object_label, tclass, requested):
	if interface != 0:
		if binary_path == "" and vm_area_name == "":
			print "Interface without binary path or VM area name ", hex(interface), " " , binary_path
			sys.exit(0)
	# If there is an interface but no VM area, assume any 
	# VM area 
	if binary_path != "" and vm_area_name == "" and interface != 0:
		vm_area_name = binary_path
	intarray = ctypes.c_uint * 2
	ia = intarray(0, 0)
	return pft_default_matches(interface, script_filename, 0, script_line_number, binary_path, 0, vm_area_name, 0, 
			process_label, ia, object_label, ia, tclass, requested)

def create_pft_entry(id, pft_default_matches, pft_match_list, pft_target, last_rule_in_chain):
	# target_offset = size of matches + 1
	# next offset = size of matches + size of target + 1 = target_offset + size of target
	next_offset = 0
	target_offset = 0
	for match_entry in pft_match_list:
		target_offset += match_entry.match_size
	next_offset = target_offset
	next_offset += pft_target.target_size
	
	if last_rule_in_chain:
		next_offset = 0

	entry = pft_entry(id, 0, pft_default_matches, target_offset, next_offset, 0, 0)
	entry_bytes = buffer(entry)[:]
	for match_entry in pft_match_list:
		entry_bytes += buffer(match_entry)[:]
	entry_bytes += buffer(pft_target)[:]
	return entry_bytes	

def create_pft_table(table_name, entries, hooks_enabled, lsm_hooks_enabled):
	size = 0
#	chain_offsets = {} # This is used to patch next_offsets which are jumps to chains
	chain_bytes = ""

	pft_table_s = pft_table()
	pft_table_s.name = table_name
	for chain, c_bytes in entries.items():
		size += len(c_bytes)
	pft_table_s.size = size
	running_len = 0
	for i in range(PF_NR_HOOKS):
		# Find the ith default chain name 
		c_name = default_chains[i]
		pft_table_s.hook_entries[i] = running_len
		running_len += len(entries[c_name])

	"""
	pft_table_s.hook_entries[PF_HOOK_INPUT] = 0
	pft_table_s.hook_entries[PF_HOOK_OUTPUT] = len(entries['input'])
	pft_table_s.hook_entries[PF_HOOK_READ] = len(entries['input']) + len(entries['output'])
	pft_table_s.hook_entries[PF_HOOK_CREATE] = len(entries['input']) + len(entries['output']) + len(entries['read'])
	"""

	for i in range(PF_NR_HOOKS):
		# Find the ith default chain name 
		c_name = default_chains[i]
		chain_bytes += entries[c_name]

	size = running_len
	"""	
	chain_bytes += entries['input']
	chain_bytes += entries['output']
	chain_bytes += entries['read']
	chain_bytes += entries['create']
	size = len(entries['input']) + len(entries['output']) + len(entries['read']) + len(entries['create'])
	"""
	# Skip-hook optimization 
	# Hooks on which rules are registered
	for i in range(0, PF_NR_HOOKS):
		if i in hooks_enabled:
			pft_table_s.hooks_enabled[i] = 1
		else:
			pft_table_s.hooks_enabled[i] = 0
	
	i = 0
	for (t, r) in lsm_hooks_enabled:
		n = pft_lsm_hook()
		n.tclass = t
		n.requested = r
		if (i == PF_MAX_LSM_HOOKS):
			break
		pft_table_s.lsm_hooks_enabled[i] = n
		i += 1
	# Make the last entry 0
	if (i != PF_MAX_LSM_HOOKS):
		n = pft_lsm_hook()
		n.tclass = 0
		n.requested = 0
		pft_table_s.lsm_hooks_enabled[i] = n

	# Reset count of number of user-defined chains
	pft_table_s.num_chains = 0
	
	for chain, c_bytes in entries.items():
#		if chain == "input" or chain == "output" or chain == "read" or chain == "create":
		if chain in default_chains:
			continue
		chain_bytes += c_bytes
		# pft_chain contains same details as in chain_offsets, but
		# for the kernel. 
		pft_chain_s = pft_chain()
		pft_chain_s.name = chain
		pft_chain_s.chain_offset = size
#		chain_offsets[chain] = size

		pft_table_s.chains[pft_table_s.num_chains] = pft_chain_s
		pft_table_s.num_chains += 1
		size += len(c_bytes)
	
	pft_table_bytes = buffer(pft_table_s)[:]
	pft_table_bytes += chain_bytes

	return pft_table_bytes #, chain_offsets

def create_pft_chain_target(chain_name):
	pft_target_s = pft_target()
	pft_target_s.target_size = ctypes.sizeof(pft_target)
	pft_target_s.name = chain_name
	pft_target_s.context_mask = 0
	return pft_target_s

