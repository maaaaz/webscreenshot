#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# This file is part of webscreenshot.
#
# Copyright (C) 2020, Thomas Debize <tdebize at mail.com>
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

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import re
import os
import sys
import subprocess
import datetime
import time
import signal
import multiprocessing
import itertools
import shlex
import logging
import errno
import argparse
import base64
import io

# Python 2 and 3 compatibility
if (sys.version_info < (3, 0)):
    os_getcwd = os.getcwdu
    izip = itertools.izip
    
else:
    os_getcwd = os.getcwd
    izip = zip

# Script version
VERSION = '2.94'

# Options definition
parser = argparse.ArgumentParser()

main_grp = parser.add_argument_group('Main parameters')
main_grp.add_argument('URL', help = 'Single URL target given as a positional argument', nargs = '?')
main_grp.add_argument('-i', '--input-file', help = '<INPUT_FILE> text file containing the target list. Ex: list.txt')
main_grp.add_argument('-o', '--output-directory', help = '<OUTPUT_DIRECTORY> (optional): screenshots output directory (default \'./screenshots/\')')
main_grp.add_argument('-w', '--workers', help = '<WORKERS> (optional): number of parallel execution workers (default 4)', default = 4)
main_grp.add_argument('-v', '--verbosity', help = '<VERBOSITY> (optional): verbosity level, repeat it to increase the level { -v INFO, -vv DEBUG } (default verbosity ERROR)', action = 'count', default = 0)
main_grp.add_argument('--no-error-file', help = '<NO_ERROR_FILE> (optional): do not write a file with the list of URL of failed screenshots (default false)', action = 'store_true', default = False)
main_grp.add_argument('-z', '--single-output-file', help = '<SINGLE_OUTPUT_FILE> (optional): name of a file which will be the single output of all inputs. Ex. test.png')

proc_grp = parser.add_argument_group('Input processing parameters')
proc_grp.add_argument('-p', '--port', help = '<PORT> (optional): use the specified port for each target in the input list. Ex: -p 80')
proc_grp.add_argument('-s', '--ssl', help = '<SSL> (optional): enforce SSL/TLS for every connection', action = 'store_true', default = False)
proc_grp.add_argument('-m', '--multiprotocol', help = '<MULTIPROTOCOL> (optional): perform screenshots over HTTP and HTTPS for each target', action = 'store_true', default = False) 

renderer_grp = parser.add_argument_group('Screenshot renderer parameters')
renderer_grp.add_argument('-r', '--renderer', help = '<RENDERER> (optional): renderer to use among \'phantomjs\' (legacy but best results), \'chrome\', \'chromium\', \'edgechromium\', \'firefox\' (version > 57) (default \'phantomjs\')', choices = ['phantomjs', 'chrome', 'chromium', 'edgechromium', 'firefox'], type=str.lower, default = 'phantomjs')
renderer_grp.add_argument('--renderer-binary', help = '<RENDERER_BINARY> (optional): path to the renderer executable if it cannot be found in $PATH')
renderer_grp.add_argument('--no-xserver', help = '<NO_X_SERVER> (optional): if you are running without an X server, will use xvfb-run to execute the renderer (by default, trying to detect if DISPLAY environment variable exists', action = 'store_true', default = ('DISPLAY' not in os.environ) and ("win32" not in sys.platform.lower()))

image_grp = parser.add_argument_group('Screenshot image parameters')
image_grp.add_argument('--window-size', help = '<WINDOW_SIZE> (optional): width and height of the screen capture (default \'1200,800\')', default = '1200,800')
image_grp.add_argument('-f', '--format', help = '<FORMAT> (optional, phantomjs only): specify an output image file format, "pdf", "png", "jpg", "jpeg", "bmp" or "ppm" (default \'png\')', choices = ['pdf', 'png', 'jpg', 'jpeg', 'bmp', 'ppm'], type=str.lower, default = 'png')
image_grp.add_argument('-q', '--quality', help = '<QUALITY> (optional, phantomjs only): specify the output image quality, an integer between 0 and 100 (default 75)', metavar="[0-100]", choices = range(0,101), type = int, default = 75)
image_grp.add_argument('--ajax-max-timeouts', help = '<AJAX_MAX_TIMEOUTS> (optional, phantomjs only): per AJAX request, and max URL timeout in milliseconds (default \'1400,1800\')', default = '1400,1800')
image_grp.add_argument('--crop', help = '<CROP> (optional, phantomjs only): rectangle <t,l,w,h> to crop the screen capture to (default to WINDOW_SIZE: \'0,0,w,h\'), only numbers, w(idth) and h(eight). Ex. "10,20,w,h"')
image_grp.add_argument('--custom-js', help = '<CUSTOM_JS> (optional, phantomjs only): path of a file containing JavaScript code to be executed before taking the screenshot. Ex: js.txt')

image_grp = parser.add_argument_group('Screenshot label parameters')
image_grp.add_argument('-l', '--label', help = '<LABEL> (optional): for each screenshot, create another one displaying inside the target URL (requires imagemagick)', action = 'store_true', default = False)
image_grp.add_argument('--label-size', help = '<LABEL_SIZE> (optional): font size for the label (default 60)', type = int, default = 60)
image_grp.add_argument('--label-bg-color', help = '<LABEL_BACKGROUND_COLOR> (optional): label imagemagick background color (default NavajoWhite)', default = "NavajoWhite")
image_grp.add_argument('--imagemagick-binary', help = '<LABEL_BINARY> (optional): path to the imagemagick binary (magick or convert) if it cannot be found in $PATH')

http_grp = parser.add_argument_group('HTTP parameters')
http_grp.add_argument('-c', '--cookie', help = '<COOKIE_STRING> (optional): cookie string to add. Ex: -c "JSESSIONID=1234; YOLO=SWAG"')
http_grp.add_argument('-a', '--header', help = '<HEADER> (optional): custom or additional header. Repeat this option for every header. Ex: -a "Host: localhost" -a "Foo: bar"', action = 'append')

http_grp.add_argument('-u', '--http-username', help = '<HTTP_USERNAME> (optional): specify a username for HTTP Basic Authentication.')
http_grp.add_argument('-b', '--http-password', help = '<HTTP_PASSWORD> (optional): specify a password for HTTP Basic Authentication.')

conn_grp = parser.add_argument_group('Connection parameters')
conn_grp.add_argument('-P', '--proxy', help = '<PROXY> (optional): specify a proxy. Ex: -P http://proxy.company.com:8080')
conn_grp.add_argument('-A', '--proxy-auth', help = '<PROXY_AUTH> (optional): provides authentication information for the proxy. Ex: -A user:password')
conn_grp.add_argument('-T', '--proxy-type', help = '<PROXY_TYPE> (optional): specifies the proxy type, "http" (default), "none" (disable completely), or "socks5". Ex: -T socks')
conn_grp.add_argument('-t', '--timeout', help = '<TIMEOUT> (optional): renderer execution timeout in seconds (default 30 sec)', default = 30)

# renderer binaries, hoping to find it in a $PATH directory
## Be free to change them to your own full-path location 
PHANTOMJS_BIN = 'phantomjs'
CHROME_BIN = 'google-chrome'
CHROMIUM_BIN = 'chromium'
FIREFOX_BIN = 'firefox'
XVFB_BIN = "xvfb-run -a"
IMAGEMAGICK_BIN = "convert"

WEBSCREENSHOT_JS = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), './webscreenshot.js'))
SCREENSHOTS_DIRECTORY = os.path.abspath(os.path.join(os_getcwd(), './screenshots/'))
FAILED_SCREENSHOTS_FILE = os.path.abspath(os.path.join(os_getcwd(), './webscreenshots_failed.txt'))

# Logger definition
LOGLEVELS = {0 : 'ERROR', 1 : 'INFO', 2 : 'DEBUG'}
logger_output = logging.StreamHandler(sys.stdout)
logger_output.setFormatter(logging.Formatter('[%(levelname)s][%(name)s] %(message)s'))

logger_gen = logging.getLogger("General")
logger_gen.addHandler(logger_output)

# Macros
SHELL_EXECUTION_OK = 0
SHELL_EXECUTION_ERROR = -1
PHANTOMJS_HTTP_AUTH_ERROR_CODE = 2

CONTEXT_RENDERER = 'renderer'
CONTEXT_IMAGEMAGICK = 'imagemagick'

# Handful patterns
p_ipv4_elementary = r'(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})'
p_domain = r'[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]+'
p_port = r'\d{0,5}'
p_resource = r'(?:/(?P<res>.*))?'

full_uri_domain = re.compile(r'^(?P<protocol>http(?:|s))://(?P<host>%s|%s)(?::(?P<port>%s))?%s$' % (p_domain, p_ipv4_elementary, p_port, p_resource))

fqdn_and_port = re.compile(r'^(?P<host>%s):(?P<port>%s)%s$' % (p_domain, p_port, p_resource))
fqdn_only = re.compile(r'^(?P<host>%s)%s$' % (p_domain, p_resource))

ipv4_and_port = re.compile(r'^(?P<host>%s):(?P<port>%s)%s' % (p_ipv4_elementary, p_port, p_resource))
ipv4_only = re.compile(r'^(?P<host>%s)%s$' % (p_ipv4_elementary, p_resource))

entry_from_csv = re.compile(r'^(?P<host>%s|%s)\s+(?P<port>\d+)$' % (p_domain, p_ipv4_elementary))

# Handful functions
def is_windows():
    """
        Are we running on Windows or not ?
    """
    return "win32" in sys.platform.lower()

def init_worker():
    """ 
        Tell the workers to ignore a global SIGINT interruption
    """
    signal.signal(signal.SIGINT, signal.SIG_IGN)

def kill_em_all(sig, frame):
    """
        Terminate all processes while capturing a SIGINT from the user
    """
    logger_gen.info('CTRL-C received, exiting')
    if is_windows():
        multiprocessing.sys.exit(1)
    
    else:
        pid = os.getpid()
        pgid = os.getpgid(pid)
        sid = os.getsid(os.getpid())
        
        # if launched with --no-xserver
        if pid == sid:
            os.killpg(pgid, signal.SIGKILL)
        else:
            time.sleep(4)
            multiprocessing.sys.exit(1)

def shell_exec(url, command, options, context):
    """
        Execute a shell command following a timeout
        Taken from http://howto.pui.ch/post/37471155682/set-timeout-for-a-shell-command-in-python
    """
    global SHELL_EXECUTION_OK, SHELL_EXECUTION_ERROR
    
    logger_url = logging.getLogger("%s" % url)
    logger_url.setLevel(options.log_level)
    
    timeout = int(options.timeout)
    start = datetime.datetime.now()
    
    def group_subprocesses():
        if options.no_xserver and not(is_windows()):
            os.setsid()
    
    def close_subfds(s):
        s.stdout.close()
        s.stderr.close()
    
    try :
        if is_windows():
            p = subprocess.Popen(shlex.split(command, posix=not(is_windows())), shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        else:
            p = subprocess.Popen(shlex.split(command, posix=not(is_windows())), shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=group_subprocesses)
        
        # binaries timeout
        while p.poll() is None:
            time.sleep(0.1)
            now = datetime.datetime.now()
            if (now - start).seconds > timeout:
                logger_url.debug("Shell command PID %s reached the timeout, killing it now" % p.pid)
                logger_url.error("Screenshot somehow failed\n")
                
                close_subfds(p)
                
                if is_windows():
                    p.send_signal(signal.SIGTERM)
                else:
                    if options.no_xserver:
                        pgid = os.getpgid(p.pid)
                        os.killpg(pgid, signal.SIGKILL)
                    else:
                        p.send_signal(signal.SIGKILL)
                
                return SHELL_EXECUTION_ERROR
        
        retval = p.poll()
        close_subfds(p)
        
        if retval != SHELL_EXECUTION_OK:
            if retval == PHANTOMJS_HTTP_AUTH_ERROR_CODE:
                # HTTP Authentication request
                logger_url.error("HTTP Authentication requested, try to pass credentials with -u and -b options")
            else:
                # Phantomjs general error
                logger_url.error("Shell command PID %s returned an abnormal error code: '%s'" % (p.pid,retval))
                logger_url.error("Screenshot somehow failed\n")
                    
            return SHELL_EXECUTION_ERROR
        
        else:
            logger_url.debug("Shell command PID %s ended normally" % p.pid)
            logger_url.info("Screenshot OK\n")
            return SHELL_EXECUTION_OK
    
    except OSError as e:
        if e.errno and e.errno == errno.ENOENT :
            default_message = '%s binary could not have been found in your current PATH environment variable, exiting' % context
            
            if context == CONTEXT_RENDERER:
                if options.no_xserver and not is_windows():
                    logger_url.error('No X server has been found and the xvfb-run binary could not be found, please install xvfb on your system')
                else:
                    logger_url.error(default_message)
            
            elif context == CONTEXT_IMAGEMAGICK:
                logger_url.error(default_message)
            
            return SHELL_EXECUTION_ERROR
        
    except Exception as err:
        logger_gen.error('Unknown error: %s, exiting' % err)
        return SHELL_EXECUTION_ERROR

def filter_bad_filename_chars_and_length(filename):
    """
        Filter bad chars for any filename
    """
    # Before, just avoid triple underscore escape for the classic '://' pattern, and length (max filename length is 255 on common OSes, but some renderer do not support that length while passing arguments for execution)
    filename = filename.replace('://', '_')[:129]
    
    return re.sub(r'[^\w\-_\. ]', '_', filename)

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
    tab = { 'full_uri_domain'       : full_uri_domain,
            'fqdn_only'             : fqdn_only,
            'fqdn_and_port'         : fqdn_and_port, 
            'ipv4_and_port'         : ipv4_and_port, 
            'ipv4_only'             : ipv4_only, 
            'entry_from_csv'        : entry_from_csv }
    
    for name, regex in tab.items():
        validator = regex.match(line)
        if validator:
            return extract_all_matched_named_groups(regex, validator)

def parse_targets(options):
    """
        Parse list and convert each target to valid URI with port(protocol://foobar:port) 
    """
    
    target_list = []
    
    if options.input_file != None:
        with open(options.input_file,'rb') as fd_input:
            try:
                lines = [l.decode('utf-8').strip() for l in fd_input.readlines()]
            
            except UnicodeDecodeError as e:
                logger_gen.error('Your input file is not UTF-8 encoded, please encode it before using this script')
                sys.exit(1)
    else:
        lines = [options.URL]
        
    for index, line in enumerate(lines, start=1):
        matches = entry_format_validator(line)
        
        # pass if line can be recognized as a correct input, or if no 'host' group could be found with all the regexes
        if matches == None or not('host' in matches.keys()):
            logger_gen.warning("Line %s '%s' could not have been recognized as a correct input" % (index, line))
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
                
                # if port is 443 and no protocol has been found earlier, assume protocol is https
                if port == 443 and not('protocol' in matches.keys()):
                    protocol = 'https'
            else:
                port = 443 if protocol == 'https' else 80
            
            # No resource URI by default
            if 'res' in matches.keys():
                res = "/" + str(matches['res'])
            else:
                res = ''
            
            # perform screenshots over HTTP and HTTPS for each target
            if options.multiprotocol:
                final_uri_http_port = int(matches['port']) if 'port' in matches.keys() else 80
                final_uri_http = '%s://%s:%s%s' % ('http', host, final_uri_http_port, res)
                target_list.append(final_uri_http)
                logger_gen.info("'%s' has been formatted as '%s' with supplied overriding options" % (line, final_uri_http))
                
                
                final_uri_https_port = int(matches['port']) if 'port' in matches.keys() else 443
                final_uri_https = '%s://%s:%s%s' % ('https', host, final_uri_https_port, res)
                target_list.append(final_uri_https)
                logger_gen.info("'%s' has been formatted as '%s' with supplied overriding options" % (line, final_uri_https))
            
            else:
                final_uri = '%s://%s:%s%s' % (protocol, host, port, res)
                target_list.append(final_uri)

                logger_gen.info("'%s' has been formatted as '%s' with supplied overriding options" % (line, final_uri))
    
    return target_list

def craft_bin_path(options, context=CONTEXT_RENDERER):
    """
        Craft the proper binary path for renderer 
    """
    global PHANTOMJS_BIN, CHROME_BIN, CHROMIUM_BIN, FIREFOX_BIN, XVFB_BIN, IMAGEMAGICK_BIN
    
    final_bin = []
    
    if context == CONTEXT_RENDERER:
        if options.no_xserver:
            final_bin.append(XVFB_BIN)
        
        if options.renderer_binary != None: 
            final_bin.append(os.path.join(options.renderer_binary))
        
        else:
            if options.renderer == 'phantomjs':
                final_bin.append(PHANTOMJS_BIN)
            
            elif options.renderer == 'chrome':
                final_bin.append(CHROME_BIN)
            
            elif options.renderer == 'chromium':
                final_bin.append(CHROMIUM_BIN)
            
            elif options.renderer == 'firefox':
                final_bin.append(FIREFOX_BIN)
    
    elif context == CONTEXT_IMAGEMAGICK:
        if options.imagemagick_binary != None:
            final_bin.append(os.path.join(options.imagemagick_binary))
        
        else:
            final_bin.append(IMAGEMAGICK_BIN)
    
    return " ".join(final_bin)

def craft_arg(param):
    """
        Craft arguments with proper quotes
    """
    if is_windows():
        return '%s' % param
    else:
        return '"%s"' % param

def launch_cmd(logger, url, cmd_parameters, options, context):
    """
        Launch the actual command
    """
    cmd = " ".join(cmd_parameters)
    logger.debug("Shell command to be executed\n'%s'\n" % cmd)
    execution_retval = shell_exec(url, cmd, options, context)
    
    return execution_retval

def craft_output_filename_and_format(url, options):
    """
        Craft the output filename and format
    """
    output_format = options.format if options.renderer == 'phantomjs' else 'png'
    
    if options.single_output_file:
        if options.single_output_file.lower().endswith('.%s' % output_format):
            output_filename = os.path.abspath(filter_bad_filename_chars_and_length(options.single_output_file))
        else:
            output_filename = os.path.abspath(filter_bad_filename_chars_and_length('%s.%s' % (options.single_output_file, output_format)))
        
    else:
        output_filename = os.path.join(options.output_directory, ('%s.%s' % (filter_bad_filename_chars_and_length(url), output_format)))
    
    return output_format, output_filename

def craft_cmd(url_and_options):
    """
        Craft the correct command with url and options
    """
    global logger_output, WEBSCREENSHOT_JS, SHELL_EXECUTION_OK, SHELL_EXECUTION_ERROR
    
    url, options = url_and_options
    
    logger_url = logging.getLogger("%s" % url)
    logger_url.addHandler(logger_output)
    logger_url.setLevel(options.log_level)
    
    output_format, output_filename = craft_output_filename_and_format(url, options)
        
    # PhantomJS renderer
    if options.renderer == 'phantomjs':
        # If you ever want to add some voodoo options to the phantomjs command to be executed, that's here right below
        cmd_parameters = [ craft_bin_path(options),
                           '--ignore-ssl-errors=true',
                           '--ssl-protocol=any',
                           '--ssl-ciphers=ALL' ]
        
        cmd_parameters.append("--proxy %s" % options.proxy) if options.proxy != None else None
        cmd_parameters.append("--proxy-auth %s" % options.proxy_auth) if options.proxy_auth != None else None
        cmd_parameters.append("--proxy-type %s" % options.proxy_type) if options.proxy_type != None else None

        cmd_parameters.append('%s url_capture=%s output_file=%s' % (craft_arg(WEBSCREENSHOT_JS), url, craft_arg(output_filename)))
        
        cmd_parameters.append('header="Cookie: %s"' % options.cookie.rstrip(';')) if options.cookie != None else None
        
        if options.http_username != None:
            if options.http_password != None:
                basic_authentication_header = base64.b64encode(str("%s:%s" % (options.http_username, options.http_password)).encode()).decode()
            
            else:
                basic_authentication_header = base64.b64encode(str("%s:" % (options.http_username)).encode()).decode()
            
            cmd_parameters.append('header="Authorization: Basic %s"' % basic_authentication_header)
        
        width = options.window_size.split(',')[0]
        height = options.window_size.split(',')[1]
        
        cmd_parameters.append('width=%d' % int(width))
        cmd_parameters.append('height=%d' % int(height))
        
        cmd_parameters.append('format=%s' % options.format)
        cmd_parameters.append('quality=%d' % int(options.quality))
        
        cmd_parameters.append('ajaxtimeout=%d' % int(options.ajax_max_timeouts.split(',')[0]))
        cmd_parameters.append('maxtimeout=%d' % int(options.ajax_max_timeouts.split(',')[1]))
        
        if options.crop != None:
            crop_rectangle = options.crop.replace('w', width).replace('h', height)
            cmd_parameters.append('crop="%s"' % crop_rectangle)
        
        if options.header:
            for header in options.header:
                cmd_parameters.append('header="%s"' % header.rstrip(';'))
       
        if options.custom_js and os.path.exists(options.custom_js):
            cmd_parameters.append('customjs=%s' % craft_arg(os.path.abspath(options.custom_js)))
       
    
    # Chrome and chromium renderers
    elif (options.renderer == 'chrome') or (options.renderer == 'chromium') or (options.renderer == 'edgechromium'): 
        cmd_parameters =  [ craft_bin_path(options),
                            '--allow-running-insecure-content',
                            '--ignore-certificate-errors',
                            '--ignore-urlfetcher-cert-requests',
                            '--reduce-security-for-testing',
                            '--no-sandbox',
                            '--headless',
                            '--disable-gpu',
                            '--hide-scrollbars',
                            '--incognito' if (options.renderer == 'chrome') or (options.renderer == 'chromium') else '-inprivate',
                            '-screenshot=%s' % craft_arg(output_filename),
                            '--window-size=%s' % options.window_size,
                            '%s' % craft_arg(url) ]
        cmd_parameters.append('--proxy-server=%s' % options.proxy) if options.proxy != None else None
    
    # Firefox renderer
    elif options.renderer == 'firefox': 
        cmd_parameters =  [ craft_bin_path(options),
                            '--new-instance',
                            '--screenshot=%s' % craft_arg(output_filename),
                            '--window-size=%s' % options.window_size,
                            '%s' % craft_arg(url) ]
                            
    execution_retval = launch_cmd(logger_url, url, cmd_parameters, options, CONTEXT_RENDERER)
    
    # ImageMagick URL embedding
    if options.label and execution_retval == SHELL_EXECUTION_OK:
        output_filename_label = os.path.join(options.output_directory, ('%s_with_label.%s' % (filter_bad_filename_chars_and_length(url), output_format)))
        cmd_parameters = [ craft_bin_path(options, 'imagemagick'),
                           craft_arg(output_filename),
                           '-pointsize %s' % options.label_size,
                           '-gravity Center',
                           '-background %s' % options.label_bg_color,
                           "label:'%s'" % url,
                           '+swap',
                           '-append %s' % craft_arg(output_filename_label) ]
        
        execution_retval_label = launch_cmd(logger_url, url, cmd_parameters, options, CONTEXT_IMAGEMAGICK)
    
    return execution_retval, url

def take_screenshot(url_list, options):
    """
        Launch the screenshot workers
        Thanks http://noswap.com/blog/python-multiprocessing-keyboardinterrupt
    """
    global SHELL_EXECUTION_OK, SHELL_EXECUTION_ERROR
    
    screenshot_number = len(url_list)
    print("[+] %s URLs to be screenshot" % screenshot_number)
    
    pool = multiprocessing.Pool(processes=int(options.workers), initializer=init_worker)
    
    taken_screenshots = [r for r in pool.imap(func=craft_cmd, iterable=izip(url_list, itertools.repeat(options)))]
    
    pool.close()
    pool.join()
    
    screenshots_error_url = [url for retval, url in taken_screenshots if retval == SHELL_EXECUTION_ERROR]
    screenshots_error = sum(retval == SHELL_EXECUTION_ERROR for retval, url in taken_screenshots)
    screenshots_ok = int(screenshot_number - screenshots_error)
    
    print("[+] %s actual URLs screenshot" % screenshots_ok)
    print("[+] %s error(s)" % screenshots_error)
    
    if screenshots_error != 0:
        if not(options.no_error_file):
            with io.open(FAILED_SCREENSHOTS_FILE, 'w', newline='\n') as fd_out:
                for url in screenshots_error_url:
                    fd_out.write(url + '\n')
                    print("    %s" % url)
        else:
            for url in screenshots_error_url:
                print("    %s" % url)

    return None

def main():
    """
        Dat main
    """
    global VERSION, SCREENSHOTS_DIRECTORY, LOGLEVELS
    signal.signal(signal.SIGINT, kill_em_all)
    
    print('webscreenshot.py version %s\n' % VERSION)
    
    options = parser.parse_args()
    
    try :
        options.log_level = LOGLEVELS[options.verbosity]
        logger_gen.setLevel(options.log_level)
    except :
        parser.error("Please specify a valid log level")
        
    if (options.input_file == None) and (options.URL == None):
        parser.error('Please specify a valid input file or a valid URL')
    
    if (options.input_file != None) and (options.URL != None):
        parser.error('Please specify either an input file or an URL')
    
    if options.single_output_file:
        options.workers = 1
    
    if options.output_directory != None:
        options.output_directory = os.path.join(os_getcwd(), options.output_directory)
    else:
        options.output_directory = SCREENSHOTS_DIRECTORY
    
    logger_gen.debug("Options: %s\n" % options)
    if not os.path.exists(options.output_directory):
        logger_gen.info("'%s' does not exist, will then be created" % options.output_directory)
        os.makedirs(options.output_directory)
    
    if options.crop != None:
        if len(options.crop.split(',')) != 4:
            parser.error('Please specify a valid crop rectangle')
    
    url_list = parse_targets(options)
    
    take_screenshot(url_list, options)
    
    return None

if __name__ == "__main__" :
    main()