#!/usr/bin/env python
# -*- coding: utf-8 -*-

# This file is part of webscreenshot.
#
# Copyright (C) 2013, Thomas Debize <tdebize at mail.com>
# All rights reserved.
#
# webscreenshot is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# webscreenshot is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with webscreenshot.  If not, see <http://www.gnu.org/licenses/>.

import re
import os
import sys
import subprocess
import datetime
import time
import signal
import multiprocessing
import logging

# OptionParser imports
from optparse import OptionParser

# Options definition
option_0 = { 'name' : ('-i', '--input-file'), 'help' : '<INPUT_FILE>: text file containing the target list. Ex: list.txt', 'nargs' : 1}
option_1 = { 'name' : ('-o', '--output-directory'), 'help' : '<OUTPUT_DIRECTORY>: screenshots output directory (default \'./screenshots/\')', 'nargs' : 1}
option_2 = { 'name' : ('-P', '--proxy'), 'help' : '<PROXY>: Specify a proxy. Ex: -P http://proxy.company.com:8080'}
option_3 = { 'name' : ('-A', '--proxy-auth'), 'help' : '<PROXY_AUTH>: Provides authentication information for the proxy. Ex: -A user:password'}
option_4 = { 'name' : ('-p', '--port'), 'help' : '<PORT>: use the specified port for each target in the input list. Ex: -p 80', 'nargs' : 1}
option_5 = { 'name' : ('-s', '--ssl'), 'help' : '<SSL>: enforce ssl for every connection', 'action' : 'store_true', 'default' : 'False'}
option_6 = { 'name' : ('-t', '--timeout'), 'help' : '<TIMEOUT>: phantomjs execution timeout in seconds (default 30 sec)', 'default' : '30', 'nargs' : 1}
option_7 = { 'name' : ('-w', '--workers'), 'help' : '<WORKERS>: number of parallel execution workers (default 3)', 'default' : '3', 'nargs' : 1}
option_8 = { 'name' : ('-l', '--log-level'), 'help' : '<LOG_LEVEL> verbosity level { DEBUG, INFO, WARN, ERROR, CRITICAL } (default ERROR)', 'default' : 'ERROR', 'nargs' : 1 }

options = [option_0, option_1, option_2, option_3, option_4, option_5, option_6, option_7, option_8]
# Script version
VERSION = '1.1'

# phantomjs binary, hoping to find it in a $PATH directory
## Be free to change it to your own full-path location 
PHANTOMJS_BIN = 'phantomjs'
SCREENSHOTS_DIRECTORY = os.path.abspath(os.path.join(os.getcwdu(), './screenshots/'))

# Logger definition
logging.basicConfig(level=logging.ERROR, format='[%(levelname)s][%(name)s] %(message)s',)
logger_gen = logging.getLogger("General")

# Macros
PID_LIST = []
SHELL_EXECUTION_OK = 0
SHELL_EXECUTION_ERROR = -1

# Handful patterns
p_ipv4_elementary = '(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})'
p_domain = '[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,6}'
p_port = '\d{0,5}'
p_resource = '(?:/(?P<res>.*))?'

full_uri_domain = re.compile('^(?P<protocol>http(?:|s))://(?P<host>%s|%s)(?::(?P<port>%s))?%s$' % (p_domain, p_ipv4_elementary, p_port, p_resource))

fqdn_and_port = re.compile('^(?P<host>%s):(?P<port>%s)%s$' % (p_domain, p_port, p_resource))
fqdn_only = re.compile('^(?P<host>%s)%s$' % (p_domain, p_resource))

ipv4_and_port = re.compile('^(?P<host>%s):(?P<port>%s)%s' % (p_ipv4_elementary, p_port, p_resource))
ipv4_only = re.compile('^(?P<host>%s)%s$' % (p_ipv4_elementary, p_resource))

entry_from_csv = re.compile('^(?P<host>%s)\s+(?P<port>\d+)$' % p_ipv4_elementary)

# Handful functions
def kill_em_all(signal, frame):
	"""
		Kill any pending screenshot process while capturing a SIGINT from the user
	"""
	global PID_LIST

	for pid in PID_LIST:
		os.kill(int(pid), signal.SIGKILL)
		logger_gen.info("trying to kill PID %s" % pid)
	
	sys.exit(0)
	
def shell_exec(url, command):
	"""
		Execute a shell command following a timeout
		Taken from http://howto.pui.ch/post/37471155682/set-timeout-for-a-shell-command-in-python
	"""
	global options, SHELL_EXECUTION_OK, SHELL_EXECUTION_ERROR, PID_LIST
	
	logger_url = logging.getLogger("%s" % url)
	logger_url.setLevel(options.log_level)
	
	timeout = int(options.timeout)
	start = datetime.datetime.now()
	
	p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	PID_LIST.append(p.pid)
	
	while p.poll() is None:
		time.sleep(0.1)
		now = datetime.datetime.now()
		if (now - start).seconds > timeout:
			logger_url.debug("Shell command PID %s reached the timeout, killing it now" % p.pid)
			os.kill(p.pid, signal.SIGKILL)
			os.waitpid(-1, os.WNOHANG)
			return SHELL_EXECUTION_ERROR
	
	logger_url.debug("Shell command PID %s ended normally" % p.pid)
	return SHELL_EXECUTION_OK

def filter_bad_filename_chars(filename):
	"""
		Filter bad chars for any filename
	"""
	# Just avoiding triple underscore escape for the classic '://' pattern
	filename = filename.replace('://', '_')
	
	return re.sub('[^\w\-_\. ]', '_', filename)

def extract_all_matched_named_groups(regex, match):
	"""
		Return a set of all extractable matched parameters.
		>>> full_uri_domain.groupindex
		{'domain': 1, 'port': 3}
		>>>full_uri_domain.match('http://8.8.8.8:80').group('domain')
		'8.8.8.8'
		>>>extract_all_matched_named_groups() => {'domain': '8.8.8.8', 'port': '80'}
			
	"""
	result = {}
	for name, id in regex.groupindex.items():
		matched_value = match.group(name)
		if matched_value != None: result[name] = matched_value
	
	return result
	
def entry_format_validator(line):
	"""
		Validate the current line against several regexes and return matched parameters (ip, domain, port etc.)
	"""
	tab = {	'full_uri_domain' 		: full_uri_domain,
			'fqdn_only'				: fqdn_only,
			'fqdn_and_port' 		: fqdn_and_port, 
			'ipv4_and_port' 		: ipv4_and_port, 
			'ipv4_only' 			: ipv4_only, 
			'entry_from_csv'		: entry_from_csv
	}
	
	for name, regex in tab.items():
		validator = regex.match(line)
		if validator:
			return extract_all_matched_named_groups(regex, validator)

def parse_targets(fd):
	"""
		Parse list and convert each target to valid URI with port(protocol://foobar:port) 
	"""
	global options
	
	target_list = []

	with open(fd,'rb') as fd_input:
		lines = [l.lstrip().rstrip().strip() for l in fd_input.readlines()]
		for index, line in enumerate(lines, start=1):
			matches = entry_format_validator(line)
			
			# pass if line can be recognized as a correct input, or if no 'host' group could be found with all the regexes
			if matches == None or not('host' in matches.keys()):
				logger_gen.warn("Line %s '%s' could not have been recognized as a correct input" % (index, line))
				pass
			else:
				host = matches['host']
				
				# Protocol is 'http' by default, unless ssl is forced
				if options.ssl == True:
					protocol = 'https'
				elif 'protocol' in matches.keys():
					protocol = str(matches['protocol'])
				else:
					protocol = 'http'
				
				# Port is ('80' for http) or ('443' for https) by default, unless a specific port is supplied
				if options.port != None:
					port = options.port
				elif 'port' in matches.keys():
					port = int(matches['port'])
				else:
					port = '443' if protocol == 'https' else '80'
				
				# No resource URI by default
				if 'res' in matches.keys():
					res = str(matches['res'])
				else:
					res = None
				
				final_uri = '%s://%s:%s' % (protocol, host, port)
				final_uri = final_uri + '/%s' % res if res != None else final_uri
				target_list.append(final_uri)
				logger_gen.info("'%s' has been formatted as '%s' with supplied overriding options" % (line, final_uri))
	
	return target_list		

def craft_cmd(url):
	"""
		Craft the correct command with url and options
	"""
	global options, PHANTOMJS_BIN, SCREENSHOTS_DIRECTORY, SHELL_EXECUTION_OK, SHELL_EXECUTION_ERROR
	
	logger_url = logging.getLogger("%s" % url)
	logger_url.setLevel(options.log_level)

	output_filename = os.path.join(SCREENSHOTS_DIRECTORY, ('%s.png' % filter_bad_filename_chars(url)))
	
	# If you ever want to add some voodoo options to the phantomjs command to be executed, that's here right below
	cmd_parameters = [ 	PHANTOMJS_BIN,
						'--ignore-ssl-errors true'
	]
	
	cmd_parameters.append("--proxy %s" % options.proxy) if options.proxy != None else None
	cmd_parameters.append("--proxy-auth %s" % options.proxy_auth) if options.proxy_auth != None else None
		
	cmd_parameters.append('webscreenshot.js url_capture=%s output_file=%s' % (url, output_filename))
		
	cmd = " ".join(cmd_parameters)
	
	logger_url.debug("Shell command to be executed\n'%s'" % cmd)
	
	
	execution_retval = shell_exec(url, cmd)
	
	if execution_retval != SHELL_EXECUTION_OK:
		logger_url.error("Screenshot somehow failed")
	else:
		logger_url.info("Screenshot OK")
	
	return execution_retval
	
def take_screenshot(url_list):
	"""
		Launch the screenshot processes 
	"""
	global options, SHELL_EXECUTION_OK, SHELL_EXECUTION_ERROR
	
	screenshot_number = len(url_list)
	print "[+] %s URLs to be screenshotted" % screenshot_number
	
	pool = multiprocessing.Pool(processes=int(options.workers))
	
	taken_screenshots = [r for r in pool.imap(func=craft_cmd, iterable=url_list)]
	
	screenshots_error = sum(s == SHELL_EXECUTION_ERROR for s in taken_screenshots)
	screenshots_ok = screenshot_number - screenshots_error
	print "[+] %s actual URLs screenshotted" % screenshots_ok
	print "[+] %s errors" % screenshots_error
		
	return None
	
def main(options, arguments):
	"""
		Dat main
	"""
	global VERSION, SCREENSHOTS_DIRECTORY
	signal.signal(signal.SIGINT, kill_em_all)
	
	print 'webscreenshot.py version %s\n' % VERSION
	
	try :
		logger_gen.setLevel(options.log_level)
	except :
		parser.error("Please specify a valid log level")
	
	if (options.input_file == None):
		parser.error('Please specify a valid input file')
	
	if options.output_directory != None:
		SCREENSHOTS_DIRECTORY = os.path.abspath(os.path.abspath(os.path.join(os.getcwdu(), options.output_directory))) 
	
	logger_gen.debug("Options: %s" % options)
	if not os.path.exists(SCREENSHOTS_DIRECTORY):
		logger_gen.info("'%s' does not exist, will be then created" % SCREENSHOTS_DIRECTORY)
		os.makedirs(SCREENSHOTS_DIRECTORY)
		
	url_list = parse_targets(options.input_file)
	
	take_screenshot(url_list)
	
	return None
	

if __name__ == "__main__" :
	parser = OptionParser()
	for option in options:
		param = option['name']
		del option['name']
		parser.add_option(*param, **option)

	options, arguments = parser.parse_args()
	main(options, arguments)