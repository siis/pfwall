#!/usr/bin/python

"""
Usage: ./pftables.py [script options] [filename]

Script Options: 
	-l automatically load policy into /sys/kernel/debug/pftable_rules
	-0 Generate ruleset with only default rule for filter table (no file necessary)
	-H / -h This help screen

filename is the name of the file containing rules (one per line) in the following format: 
Rule Options: 
	-t table_name (filter|mangle)
	-A chain_name (input|output - inbuilt, can also be user-defined)
	-s source_label
	-d destination_label
	-i interface (0xhex if binary, filename:number if script, filename:0 for any line number)
	-c object_class_number
	-o operation_number
	-b binary_path
	-v vm_area_name
	-m match_mod_name [match_mod_options]
	-j target_mod_name [target_mod_options]
	# At the beginning of the line is a comment
Example: 
	# Logs all input accesses to the X server
	pftables -t filter -I input -b /usr/bin/Xorg -j log -c CONTEXT_INTERFACE 
"""

import os
import sys
import convert_single
import pft_c
import pdb 
import getopt

table_filter_input_bytes = ""
table_mangle_input_bytes = ""
table_filter_output_bytes = ""
table_mangle_output_bytes = ""

# Rules in each table, further keyed by chain
tables = {}

# Skip-hook optimization: hook-header details of table. 
table_hooks_enabled = {}
table_lsm_hooks_enabled = {}

table_filter_input_nr_entries = 0
table_mangle_input_nr_entries = 0
table_filter_output_nr_entries = 0
table_mangle_output_nr_entries = 0

PFTABLES_KERNEL_LOAD_FILE = "/sys/kernel/debug/pftable_rules"
PFTABLES_BINARY_FILE = "binary"

if len(sys.argv) < 2:
	print "./pftables.py <options> [rule_file]"
	print "-h/-H for help"
	sys.exit(0)

def usage():
    sys.stderr.write(__doc__)
    sys.exit(0)

def get_table_and_chain(string):
	args = string.split()
	table = ""
	chain = ""
	for i in range(len(args)):
		if args[i] == "-t" or args[i] == "-T":
			table = args[i + 1]
			i += 1
		if args[i] == "-A" or args[i] == "-I":
			chain = args[i + 1]
			i += 1
		if args[i].lower() == "-m" or args[i].lower() == "-j":
			break
		i += 1
	return table.lower(), chain.lower()

if __name__ == "__main__":

	only_default_rules = False # Only generate default rule? 
	direct_load = False # Load directly into kernel? 
	filename = "" # Filename to load rules from

	try: 
		optlist, args = getopt.getopt(sys.argv[1:], "lHh0")
	except getopt.GetoptError,e:
		print >> sys.stderr, "ERROR: %s" % (e)
		usage()

	for o, a in optlist:
		if o == "-h" or o == "-H":
			usage()
		elif o == "-0":
			only_default_rules = True
		elif o == "-l":
			direct_load = True
	if not only_default_rules:
		filename = args[0]
		lnum = 0

		sys.stdout.write("  ")
		sys.stdout.flush()

		lines = open(filename).readlines()
		for line in lines:
			lnum += 1
			if line[0] == '#':
				continue
			if line.strip('\n') == "":
				continue

			per_fin = int((lnum * 100) / len(lines)); 
			sys.stdout.write("\b\b" + "%02d" % per_fin)
			sys.stdout.flush()
			line = line.rstrip('\n')

			entry_bytes, hook, tclass, requested = convert_single.convert_single_rule(lnum, line.split(), False)
			# Get table and chain, and append the rule 
			table, chain = get_table_and_chain(line)

			if table not in tables.keys():
				tables[table] = {}
				table_hooks_enabled[table] = []
				table_lsm_hooks_enabled[table] = []

			if chain not in tables[table].keys():
				tables[table][chain] = ""

			tables[table][chain] += entry_bytes

			# Skip-hook optimization
			# Add information about necessary hook 
			if (hook != pft_c.PF_NON_DEFAULT_HOOK):
				if ((hook == pft_c.PF_HOOK_INPUT or hook == pft_c.PF_HOOK_OUTPUT)):
					if (tclass == 0 and requested == 0):
						table_hooks_enabled[table].append(hook)
					else:
						table_lsm_hooks_enabled[table].append((tclass, requested))
				else:
					table_hooks_enabled[table].append(hook)

	# If "-0", then add filter table 
	if pft_c.default_table not in tables.keys():
		tables[pft_c.default_table] = {}
		table_hooks_enabled[pft_c.default_table] = []
		table_lsm_hooks_enabled[pft_c.default_table] = []

	# Add policy rule to default chains and 
	# return rule to user-defined chains 
	for table, c_dict in tables.items():
		for def_chain in pft_c.default_chains:
			if def_chain not in tables[table].keys():
				tables[table][def_chain] = ""
		for c_name, c_bytes in c_dict.items():
			if c_name in pft_c.default_chains:
				policy_rule = "pftables -t " + table + " -I " + c_name + " -j accept" # Default policy 
			else:
				policy_rule = "pftables -t " + table + " -I " + c_name + " -j return" # Return to caller chain
			# hook, tclass, requested won't be used here; this is the default allow rule
			policy_rule_bytes, hook, tclass, requested = convert_single.convert_single_rule(0, policy_rule.split(), True)
			tables[table][c_name] += policy_rule_bytes

	pft_filter_table = pft_c.create_pft_table("filter", tables["filter"], table_hooks_enabled["filter"], table_lsm_hooks_enabled["filter"])

	# Kernel will patch next offsets 

	if direct_load:
		pftable_rules = open(PFTABLES_KERNEL_LOAD_FILE, "wb")
		pftable_rules.write(pft_filter_table)

	pftable_rules = open(PFTABLES_BINARY_FILE, "wb")
	pftable_rules.write(pft_filter_table)
