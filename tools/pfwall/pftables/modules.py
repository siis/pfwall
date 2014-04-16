import ConfigParser
import os
import sys
# Dealing with registering match and target modules 

match_modules_registered = {}
target_modules_registered = {}

def register_target_module(name, func):
	target_modules_registered[name.lower()] = func
	
def get_target_module_func(name):
	if name.lower() in target_modules_registered.keys():
		return target_modules_registered[name.lower()]
	else:
		return None # chain target

def register_match_module(name, func):
	match_modules_registered[name.lower()] = func
	
def get_match_module_func(name):
	return match_modules_registered[name.lower()]

def register_all():
	# Open the modules.conf file and register all modules
	configp = ConfigParser.ConfigParser()
	configp.read("modules.conf")
	match_modules = configp.get("Modules", "match").split(',')
	target_modules = configp.get("Modules", "target").split(',')

	for match_module in match_modules:
		sys.path.append('modules/match')
		module = __import__(match_module)
		match_func = getattr(module, 'match_prepare')
		register_match_module(match_module, match_func)

	for target_module in target_modules:
		sys.path.append('modules/target')
		module = __import__(target_module)
		target_func = getattr(module, 'target_prepare')
		register_target_module(target_module, target_func)
