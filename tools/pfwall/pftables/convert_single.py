#!/usr/bin/python

# pftables -t table_name -A chain_name
# -m match_mod_name [match_mod_options]
# -j target_mod_name [target_mod_options]

import sys
import os
import ctypes as ct
import modules # Match and target modules
import pft_c # C-style ctypes struct declaration

def python_strarr_to_c(str_list):
	STRARR = ct.c_char_p * len(str_list)
	str_array = STRARR()
	for i in range(0, len(str_list)):
		str_array[i] = str_list[i]
	return str_array
	
def print_format(error_str):
	print error_str
	print "pftables -t table -I chain [-m mod_name mod_args] -j target"
	sys.exit(0)

def check_empty(var, string):
	if var == "":
		print_format(string)

def convert_single_rule(id, argv, last_rule_in_chain):

	valid_tables = ["filter", "mangle"]

	table = ""
	chain = ""
	target_mod_name = ""

	# Default matches 
	interface = "0x0"
	script_filename = ""
	script_line_number = 0
	binary_path = ""
	vm_area_name = ""
	process_label = ""
	object_label = ""
	tclass = "0"
	requested = "0"
	
	# Match entry list for this rule
	match_entry_list = []

	# Target entry for this rule
	target_entry = None

	# Register modules
	modules.register_all()
	# Parse options
	i = 1
	while i < len(argv):
		if argv[i] == "-t":
			i += 1
			table = argv[i].lower()
			if table not in valid_tables:
				print_format("Table needs to be one of: " + str(valid_tables))
			i += 1
		if argv[i] == "-I" or argv[i] == "-A":
			i += 1
			chain = argv[i].lower()
			i += 1
		if argv[i] == "-i":
		  	if argv[i + 1][0] == "-":
		  		print_format("Interface requires an argument")
		  	else:
				if ":" in argv[i + 1]:
					script_filename = argv[i + 1].split(":")[0]
					script_line_number = argv[i + 1].split(":")[1]
				else:
				  	interface = argv[i + 1]
				i += 2
		if argv[i] == "-b":
		  	if argv[i + 1][0] == "-":
		  		print_format("Binary path requires an argument")
		  	else:
			  	binary_path = argv[i + 1]
				i += 2
		if argv[i] == "-v":
		  	if argv[i + 1][0] == "-":
		  		print_format("VM area name requires an argument")
		  	else:
			  	vm_area_name = argv[i + 1]
				i += 2
		if argv[i] == "-c":
		  	if argv[i + 1][0] == "-":
		  		print_format("Object class requires an argument")
		  	else:
			  	tclass = argv[i + 1]
				i += 2
		if argv[i] == "-o" or argv[i] == "-r":
		  	if argv[i + 1][0] == "-":
		  		print_format("Operation requires an argument")
		  	else:
			  	requested = argv[i + 1]
				i += 2
		if argv[i] == "-s":
		  	if argv[i + 1][0] == "-":
		  		print_format("Source label requires an argument")
		  	else:
			  	process_label = argv[i + 1]
				i += 2
		if argv[i] == "-d":
		  	if argv[i + 1][0] == "-":
		  		print_format("Destination label requires an argument")
		  	else:
			  	object_label = argv[i + 1]
				i += 2
		if argv[i] == "-m":
			# Match module
		  	match_mod_name = argv[i + 1]
			i += 2
			match_mod_args = []
			while i < len(argv) and argv[i] != "-m" and argv[i] != "-j":
				if " " in argv[i]:
					match_mod_args.append("\"" + argv[i] + "\"")
				else:
					match_mod_args.append(argv[i])
				i += 1

			# Convert string array into char** to be passed into C function
			str_array = python_strarr_to_c(match_mod_args)

			# Call the appropriate match module to convert the arguments into binary format
			mf = modules.get_match_module_func(match_mod_name)
			pft_match_entry = mf(match_mod_args)

			# Store the match entry in the list of 
			# entries for this rule
			match_entry_list.append(pft_match_entry)

#			match_lib = ct.cdll.LoadLibrary(os.getcwd() + "/pf_match_" + match_mod_name + ".so")
#			match_lib.match_mod(len(match_mod_args), str_array)
		if argv[i] == "-j":
			# Target module
			if target_mod_name != "":
				print_format("Only one target module may be specified per rule")
			target_mod_name = argv[i + 1]
			i += 2
			target_mod_args = []
			while i < len(argv) and argv[i] != "-m" and argv[i] != "-j":
				if " " in argv[i]:
					target_mod_args.append("\"" + argv[i] + "\"")
				else:
					target_mod_args.append(argv[i])
				i += 1
#			print "target_mod_name: " + target_mod_name + "\nargs: " + target_mod_args
			# Convert array into char** to be passed into C function
			# str_array = python_strarr_to_c(target_mod_args)

			# If the target module is not present, it can be that the jump is to a chain
			# Call the appropriate target module to convert the arguments into binary format
			tf = modules.get_target_module_func(target_mod_name)
			if tf == None: # Chain jump target
				pft_target_entry = pft_c.create_pft_chain_target(target_mod_name)
			else:
				pft_target_entry = tf(target_mod_args)	
			# Call the appropriate match module
			# target_lib = ct.cdll.LoadLibrary(os.getcwd() + "/pf_target_" + target_mod_name + ".so")
			# target_lib.target_mod(len(target_mod_args), str_array)
			
	# Final sanity check
	if table == "":
		table = "filter"

	# check_empty(table, "Specify a table")
	check_empty(chain, "Specify a chain")
	check_empty(target_mod_name, "Specify a target")

	# Create a pft_default_matches for this rule
	def_matches = pft_c.create_pft_default_matches(int(interface, 16), script_filename, int(script_line_number), binary_path, vm_area_name, process_label, object_label, int(tclass), int(requested))

	# Create a pft_entry out of the default matches, list of pft_match, and pft_target - returns a byte array
	pft_entry_array = pft_c.create_pft_entry(id, def_matches, match_entry_list, pft_target_entry, last_rule_in_chain)

	# Skip-hook optimization
	hook = pft_c.PF_NON_DEFAULT_HOOK

	if (chain in pft_c.default_chains_inv.keys()):
		hook = pft_c.default_chains_inv[chain]

	return pft_entry_array, hook, int(tclass), int(requested)
