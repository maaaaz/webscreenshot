#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# This file is part of webscreenshot.
#
# Copyright (C) 2019, Thomas Debize <tdebize at mail.com>
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
import requests
import json
import asyncio
import websockets

# Python 2 and 3 compatibility
if (sys.version_info < (3, 0)):
    os_getcwd = os.getcwdu
    izip = itertools.izip
    
else:
    os_getcwd = os.getcwd
    izip = zip

# Script version
VERSION = '2.91'

# Options definition
parser = argparse.ArgumentParser()

main_grp = parser.add_argument_group('Main parameters')
main_grp.add_argument('URL', help = 'Single URL target given as a positional argument', nargs = '?')
main_grp.add_argument('-i', '--input-file', help = '<INPUT_FILE> text file containing the target list. Ex: list.txt')
main_grp.add_argument('-o', '--output-directory', help = '<OUTPUT_DIRECTORY> (optional): screenshots output directory (default \'./screenshots/\')')
main_grp.add_argument('-w', '--workers', help = '<WORKERS> (optional): number of parallel execution workers (default 4)', default = 4)
main_grp.add_argument('-v', '--verbosity', help = '<VERBOSITY> (optional): verbosity level, repeat it to increase the level { -v INFO, -vv DEBUG } (default verbosity ERROR)', action = 'count', default = 0)

proc_grp = parser.add_argument_group('Input processing parameters')
proc_grp.add_argument('-p', '--port', help = '<PORT> (optional): use the specified port for each target in the input list. Ex: -p 80')
proc_grp.add_argument('-s', '--ssl', help = '<SSL> (optional): enforce ssl for every connection', action = 'store_true', default = False)
proc_grp.add_argument('-m', '--multiprotocol', help = '<MULTIPROTOCOL> (optional): perform screenshots over HTTP and HTTPS for each target', action = 'store_true', default = False) 

renderer_grp = parser.add_argument_group('Screenshot renderer parameters')
renderer_grp.add_argument('-r', '--renderer', help = '<RENDERER> (optional): renderer to use among \'phantomjs\' (legacy but best results), \'chrome\', \'chromium\', \'firefox\' (version > 57) (default \'phantomjs\')', choices = ['phantomjs', 'chrome', 'chromium', 'firefox'], type=str.lower, default = 'phantomjs')
renderer_grp.add_argument('--renderer-binary', help = '<RENDERER_BINARY> (optional): path to the renderer executable if it cannot be found in $PATH')
renderer_grp.add_argument('--no-xserver', help = '<NO_X_SERVER> (optional): if you are running without an X server, will use xvfb-run to execute the renderer', action = 'store_true', default = False)

image_grp = parser.add_argument_group('Screenshot image parameters')
image_grp.add_argument('--window-size', help = '<WINDOW_SIZE> (optional): width and height of the screen capture (default \'1200,800\')', default = '1200,800')
image_grp.add_argument('-f', '--format', help = '<FORMAT> (optional): specify an output image file format, Supported formats: PhantomJS -> "pdf", "png", "jpg", "jpeg", "bmp" or "ppm". ChromX -> "pdf", "jpg", "jpeg", or "png". (default \'png\')', choices = ['pdf', 'png', 'jpg', 'jpeg', 'bmp', 'ppm'], type=str.lower, default = 'png')
image_grp.add_argument('-q', '--quality', help = '<QUALITY> (optional, Phantomjs and ChromX[only JPEG format]): specify the output image quality, an integer between 0 and 100 (default 75)', metavar="[0-100]", choices = range(0,101), type = int, default = 75)
image_grp.add_argument('-d', '--delay', help = '<DELAY> (optional, ChromX only): specify a screen capture delay in seconds (default 0)', metavar="DELAY_SECONDS", type = int, default = 0)
image_grp.add_argument('--ajax-max-timeouts', help = '<AJAX_MAX_TIMEOUTS> (optional, phantomjs only): per AJAX request, and max URL timeout in milliseconds (default \'1400,1800\')', default = '1400,1800')
image_grp.add_argument('--crop', help = '<CROP> (optional, phantomjs and ChromeX): rectangle <t,l,w,h> to crop the screen capture to (default to WINDOW_SIZE: \'0,0,w,h\'), only numbers, w(idth) and h(eight). Ex. "10,20,w,h"')

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

WEBSCREENSHOT_JS = os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__)), './webscreenshot.js'))
SCREENSHOTS_DIRECTORY = os.path.abspath(os.path.join(os_getcwd(), './screenshots/'))

# Default devtools server (localhost).
# Used to run Chrome based browsers in remote debugging mode:
DEVTOOLS_SERVER = "http://127.0.0.1"
DEVTOOLS_PORT = 9222  # Change if it conflicts with another running service

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
CHROMX_RENDER_TIMOUT_ERROR = 3
CHROMX_CONNECTION_ERROR = 4
CHROMX_OUTPUT_FILE_ERROR = 5

# Handful patterns
p_ipv4_elementary = '(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})'
p_domain = '[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]+'
p_port = '\d{0,5}'
p_resource = '(?:/(?P<res>.*))?'
p_cookies = re.compile(r'[\s]?([^=]+)=([^;\s]+)[;]?', re.I)

full_uri_domain = re.compile('^(?P<protocol>http(?:|s))://(?P<host>%s|%s)(?::(?P<port>%s))?%s$' % (p_domain, p_ipv4_elementary, p_port, p_resource))

fqdn_and_port = re.compile('^(?P<host>%s):(?P<port>%s)%s$' % (p_domain, p_port, p_resource))
fqdn_only = re.compile('^(?P<host>%s)%s$' % (p_domain, p_resource))

ipv4_and_port = re.compile('^(?P<host>%s):(?P<port>%s)%s' % (p_ipv4_elementary, p_port, p_resource))
ipv4_only = re.compile('^(?P<host>%s)%s$' % (p_ipv4_elementary, p_resource))

entry_from_csv = re.compile('^(?P<host>%s|%s)\s+(?P<port>\d+)$' % (p_domain, p_ipv4_elementary))

# Handful functions
def is_windows():
    """
        Are we running on Windows or not ?
    """
    return "win32" in sys.platform.lower()

def getWebSocketData():
    """
        Get Browser's control websocket URL and Tab ID.
    """
    # returned data:
    result = {
        "code": "OK",
        "message": "",
        "WS": None,
        "tabID": None
    }

    try:
        # Request Browser's available pages and websockets (0.5 seconds timeout):
        response = requests.get("%s:%d/json/list" % (DEVTOOLS_SERVER, DEVTOOLS_PORT), timeout=0.5)
    except (
        requests.exceptions.ConnectTimeout,
        requests.exceptions.ConnectionError,
        requests.exceptions.InvalidURL,
        requests.exceptions.ReadTimeout
    ) as e:
        result["code"] = "ERROR"
        result["message"] = str(e)
        return result

    try:
        # Parse JSON response:
        data = json.loads(response.text)
    except (json.decoder.JSONDecodeError) as e:
        result["code"] = "ERROR"
        result["message"] = str(e)
        return result

    # In case that additional items are present in the browser
    # (like the devtools window), pick the page asociated to the URL:
    for tab in data:
        if tab["url"] == "http://127.0.0.1/?id=debugger":
            result["WS"] = tab["webSocketDebuggerUrl"]
            result["tabID"] = tab["id"]
            break
    return result

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
            logger_url.error('%s binary could not have been found in your current PATH environment variable, exiting' % context)
            return SHELL_EXECUTION_ERROR
        
    except Exception as err:
        logger_gen.error('Unknown error: %s, exiting' % err)
        return SHELL_EXECUTION_ERROR

def chromx_debugger_exec(options):
    """
        Execute ChromX browser in headless-remote debugging mode (Devtools protocol).
        When executed this way, the ChromX browser will start a server listening on the specified port.
        The most important endpoints of this server are:
        /json/close/{tabId} -> instructs the browser to close the specified tab.
        /json or /json/list -> returns a list of all available websocket targets.
                               Every tab has its own websocket URL in which it can
                               receive commands via JSON payloads.
        /json/new?{url} -> instructs the browser to open a new tab (url is optional).
                           It returns a JSON object containing the tab ID and websocket URL,
                           among other data.

        As mentioned before, every tab has its own websocket URL, in which the script can send commands.
        The complete list of supported commands can be found at:
        https://chromedevtools.github.io/devtools-protocol/
        The basic structure of a valid JSON payload is the following:
        {
            "id": 0, # An ID integer, it can be any integer.
                     # It's mainly used to associate a server response with a previous request.
            "method": <DEVTOOLS_PROTOCOL_DOMAIN.COMMAND>, # String, Ex. "Page.captureScreenshot"
            "params": { # The parameters that the command requires
                "paramX": value1,
                "paramY": value2,
                ...
            }
        }
    """
    cmd_parameters = [
        craft_bin_path(options),
        '--allow-running-insecure-content',
        # The following flag will be reforced via Devtools protocol
        # in the screenshot process, in case it's no longer supported
        # by the current browser:
        '--ignore-certificate-errors',
        '--ignore-urlfetcher-cert-requests',
        '--reduce-security-for-testing',
        '--headless',
        '--disable-gpu',
        '--hide-scrollbars',
        '--incognito',
        '--user-data-dir=.tmp',  # Work around to spawn an independant instance
        '--remote-debugging-port=%d' % DEVTOOLS_PORT,  # Devtools server's listening port
        '--window-size=%s' % options.window_size,
        '%s' % craft_arg('http://127.0.0.1/?id=debugger')
    ]
    cmd_parameters.append('--proxy-server=%s' % options.proxy) if options.proxy is not None else None
    command = " ".join(cmd_parameters)
    logger_gen.debug("Shell command to be executed\n'%s'\n" % command)

    def group_subprocesses():
        if options.no_xserver and not(is_windows()):
            os.setsid()

    try:
        if is_windows():
            p = subprocess.Popen(shlex.split(command, posix=not(is_windows())), shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        else:
            p = subprocess.Popen(shlex.split(command, posix=not(is_windows())), shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=group_subprocesses)
    except OSError as e:
        if e.errno and e.errno == errno.ENOENT:
            logger_gen.error('%s binary could not have been found in your current PATH environment variable, exiting' % 'renderer')
            return SHELL_EXECUTION_ERROR

    except Exception as err:
        logger_gen.error('Unknown error: %s, exiting' % err)
        return SHELL_EXECUTION_ERROR

async def chromx_terminate(wsserver):
    """
        Kills the Devtools server.
    """
    async with websockets.connect(wsserver) as websocket:
        raw = {
            "id": 1,
            "method": "Browser.close",
            "params": {}
        }
        request = json.dumps(raw)
        await websocket.send(request)

def filter_bad_filename_chars(filename):
    """
        Filter bad chars for any filename
    """
    # Before, just avoid triple underscore escape for the classic '://' pattern
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

def craft_bin_path(options, context='renderer'):
    global PHANTOMJS_BIN, CHROME_BIN, CHROMIUM_BIN, FIREFOX_BIN, XVFB_BIN, IMAGEMAGICK_BIN
    
    final_bin = []
    
    if context == 'renderer':
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
    
    elif context == 'imagemagick':
        if options.imagemagick_binary != None:
            final_bin.append(os.path.join(options.imagemagick_binary))
        
        else:
            final_bin.append(IMAGEMAGICK_BIN)
    
    return " ".join(final_bin)

def craft_arg(param):
    if is_windows():
        return '%s' % param
    else:
        return '"%s"' % param

def launch_cromx_subprocess(logger, url, options):
    """
        For ChromX browsers.
        Load a new target URL and trigger the screenshot process.
    """

    # Not an acutal "instance", but a new tab:
    logger.debug("Openning new browser instance")
    try:
        # Load new Chromx tab:
        response = requests.get("%s:%d/json/new" % (DEVTOOLS_SERVER, DEVTOOLS_PORT))
    except (
        requests.exceptions.ConnectTimeout,
        requests.exceptions.ConnectionError,
        requests.exceptions.InvalidURL,
        requests.exceptions.ReadTimeout
    ) as e:
        logger.error("Failed to spawn a new browser instance : %s" % str(e))
        return SHELL_EXECUTION_ERROR

    if response.status_code == 200:
        try:
            # Get some data (websocket URL, tab ID) of the browser tab asociated with the current worker.
            # Every tab has its own websocket URL (webSocketDebuggerUrl),
            # as defined in https://chromedevtools.github.io/devtools-protocol/
            tabData = json.loads(response.text)
        except (json.decoder.JSONDecodeError) as e:
            logger.error("Failed to parse Devtools server response: %s" % str(e))
            return SHELL_EXECUTION_ERROR

        logger.debug('Tab\'s websocket: %s' % tabData['webSocketDebuggerUrl'])

        output_format = None  # Output file format
        timeout = int(options.timeout)  # Screenshot timeout
        headers = {}  # User defined headers
        cookies = []  # User defined cookies
        # Screen capture region defaults, overriden by user defined "crop" parameter:
        region = [
            "0",  # Top offset (in pixels)
            "0",  # Left offset (in pixels)
            options.window_size.split(',')[0],  # Screen capture region width (in pixels)
            "0"  # Screen capture region height  (in pixels, 0 will capture full page)
        ]

        # Additional HTTP headers:
        if options.header:
            for header in options.header:
                raw_header = header.rstrip(';').split(': ')
                headers[raw_header[0]] = raw_header[1]

        # Cookies:
        if options.cookie is not None:
            raw_cookies = re.findall(p_cookies, options.cookie)
            expires = int(time.time()) + timeout + 60
            for cookie in raw_cookies:
                cookies.append(
                    {
                        "name": cookie[0],
                        "value": cookie[1],
                        "url": url,
                        "expires": expires
                    }
                )

        # Screeenshot format (JPEG, PNG or PDF), as described at:
        # https://chromedevtools.github.io/devtools-protocol/tot/Page/#method-captureScreenshot
        # https://chromedevtools.github.io/devtools-protocol/tot/Page/#method-printToPDF
        if options.format == 'png' or options.format == 'jpeg' or options.format == 'pdf':
            output_format = options.format
        elif options.format == "jpg":
            output_format = "jpeg"
        else:  # User choose a valid format, but not one supported by ChromX
            output_format = "png"  # Default format
            logger.info("%s format is not supported by the renderer, setting default instead (PNG)." % options.format.upper())

        # Screenshot file:
        output_filename = os.path.join(options.output_directory, ('%s.%s' % (filter_bad_filename_chars(url), output_format)))

        # Screen capture region (overrides default):
        if options.crop is not None:
            crop_option = options.crop.replace(
                'w', options.window_size.split(',')[0]
            ).replace(
                'h', options.window_size.split(',')[1]
            )

            region = crop_option.split(',')

        # Screenshot process.
        retval = asyncio.get_event_loop().run_until_complete(
            chromx_screenshot(
                logger=logger,
                tabID=tabData["id"],
                wsserver=tabData["webSocketDebuggerUrl"],
                URL=url,
                headers=headers,
                cookies=cookies,
                path=output_filename,
                format=output_format,
                quality=options.quality,
                width=int(region[2]),
                height=int(region[3]),
                top=int(region[0]),
                left=int(region[1]),
                delay=options.delay,
                timeout=timeout
            )
        )

        # ChromX errors go here:
        if retval != SHELL_EXECUTION_OK:
            if retval == CHROMX_RENDER_TIMOUT_ERROR:
                # Render timout
                logger.debug("Tab %s reached the timeout, it has been killed." % tabData["id"])
                logger.error("Screenshot somehow failed.\n")
            elif retval == CHROMX_CONNECTION_ERROR:
                logger.debug("Tab %s's websocket is not responding, it has been killed." % tabData["id"])
                logger.error("Screenshot somehow failed.\n")
            elif retval == CHROMX_OUTPUT_FILE_ERROR:
                logger.debug("An error ocurred while saving screenshot file.")
                logger.error("Screenshot somehow failed.\n")
            return SHELL_EXECUTION_ERROR
        else:
            logger.debug("Tab %s ended normally." % tabData["id"])
            logger.info("Screenshot OK.\n")
            return SHELL_EXECUTION_OK
    else:
        logger.error("Failed to spawn a new browser instance [Devtools server responded with status code: %d]." % response.status_code)
        return SHELL_EXECUTION_ERROR

def launch_cmd(logguer, url, cmd_parameters, options, context):
    """
        Launch the actual command
    """
    cmd = " ".join(cmd_parameters)
    logguer.debug("Shell command to be executed\n'%s'\n" % cmd)
    execution_retval = shell_exec(url, cmd, options, context)
    
    return execution_retval

def craft_cmd(url_and_options):
    """
        Craft the correct command with url and options
    """
    global logger_output, WEBSCREENSHOT_JS, SHELL_EXECUTION_OK, SHELL_EXECUTION_ERROR
    
    url, options = url_and_options
    
    logger_url = logging.getLogger("%s" % url)
    logger_url.addHandler(logger_output)
    logger_url.setLevel(options.log_level)
    
    output_format = options.format if options.renderer == 'phantomjs' else 'png'
    output_filename = os.path.join(options.output_directory, ('%s.%s' % (filter_bad_filename_chars(url), output_format)))

    # ChromX renderers:
    if (options.renderer == 'chrome') or (options.renderer == 'chromium'):
        execution_retval = launch_cromx_subprocess(logger_url, url, options)
    else:
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

        # Firefox renderer
        elif options.renderer == 'firefox': 
            cmd_parameters =  [ craft_bin_path(options),
                                '--new-instance',
                                '--screenshot=%s' % craft_arg(output_filename),
                                '--window-size=%s' % options.window_size,
                                '%s' % craft_arg(url) ]
                                
        execution_retval = launch_cmd(logger_url, url, cmd_parameters, options, 'renderer')
    
    # ImageMagick URL embedding
    if options.label and execution_retval == SHELL_EXECUTION_OK:
        output_filename_label = os.path.join(options.output_directory, ('%s_with_label.%s' % (filter_bad_filename_chars(url), output_format)))
        cmd_parameters = [ craft_bin_path(options, 'imagemagick'),
                           craft_arg(output_filename),
                           '-pointsize %s' % options.label_size,
                           '-gravity Center',
                           '-background %s' % options.label_bg_color,
                           "label:'%s'" % url,
                           '+swap',
                           '-append %s' % craft_arg(output_filename_label) ]
        
        execution_retval_label = launch_cmd(logger_url, url, cmd_parameters, options, 'imagemagick')
    
    return execution_retval, url

async def chromx_screenshot(
    logger,
    tabID,
    wsserver,
    URL,  # Target URL
    headers={},  # Additional HTTP headers
    cookies=[],  # Cookies to inject into the request
    path="screenshot.png",  # Image or PDF destination file
    format="png",  # File format
    quality=70,  # Image quality
    width=1200,  # Screen capture region width
    height=800,  # Screen capture region height
    top=0,  # Sreen capture region top offset
    left=0,  # Sreen capture region left offset
    delay=0,
    timeout=30
):
    """
        Chromium based browsers screenshot
        ( using Devtools protocol, more info at
        https://chromedevtools.github.io/devtools-protocol/ )
    """
    async def main():
        # Final screen capture region height:
        finalHeight = height

        async with websockets.client.connect(wsserver, ping_interval=None, close_timeout=60, max_size=None) as websocket:
            # Reforce certificate error ignoring (Experimental):
            # https://chromedevtools.github.io/devtools-protocol/tot/Security/#method-setIgnoreCertificateErrors
            raw = {
                "id": 1,
                "method": "Security.setIgnoreCertificateErrors",
                "params": {
                    "ignore": True
                }
            }
            request = json.dumps(raw)
            await websocket.send(request)

            # Enable Network tracking (used for setting HTTP headers and cookies):
            # https://chromedevtools.github.io/devtools-protocol/tot/Network/#method-enable
            raw = {
                "id": 10,
                "method": "Network.enable",
                "params": {}
            }
            request = json.dumps(raw)
            await websocket.send(request)
            logger.debug("Network tracking enabled.")

            # Set extra headers:
            # https://chromedevtools.github.io/devtools-protocol/tot/Network/#method-setExtraHTTPHeaders
            if len(headers) > 0:
                raw = {
                    "id": 30,
                    "method": "Network.setExtraHTTPHeaders",
                    "params": {
                        "headers": headers
                    }
                }
                request = json.dumps(raw)
                await websocket.send(request)

            # Set Cookies:
            # https://chromedevtools.github.io/devtools-protocol/1-3/Network/#method-setCookies
            if len(cookies) > 0:
                raw = {
                    "id": 31,
                    "method": "Network.setCookies",
                    "params": {
                        "cookies": cookies
                    }
                }
                request = json.dumps(raw)
                await websocket.send(request)

            # Enable page domain notifications (used for determining when the page has been loaded):
            # https://chromedevtools.github.io/devtools-protocol/tot/Page/#method-enable
            raw = {
                "id": 20,
                "method": "Page.enable",
                "params": {}
            }
            request = json.dumps(raw)
            await websocket.send(request)
            logger.debug("Page domain notifications enabled.")

            # Load target URL in the browser:
            # https://chromedevtools.github.io/devtools-protocol/tot/Page/#method-navigate
            logger.debug("Loading URL.")
            raw = {
                "id": 40,
                "method": "Page.navigate",
                "params": {
                    "url": URL,
                }
            }
            request = json.dumps(raw)
            await websocket.send(request)

            # Wait for the page to load:
            # https://chromedevtools.github.io/devtools-protocol/tot/Page/#event-loadEventFired
            while True:
                response = await websocket.recv()
                data = json.loads(response)
                if "method" in data and data["method"] == "Page.loadEventFired":
                    logger.debug("Page Ready.")
                    break

            # Disable Network tracking:
            # https://chromedevtools.github.io/devtools-protocol/tot/Network/#method-disable
            raw = {
                "id": 50,
                "method": "Network.disable",
                "params": {}
            }
            request = json.dumps(raw)
            await websocket.send(request)
            logger.debug("Network tracking disabled.")

            # Default screen capture region height (full page):
            if finalHeight == 0:
                # Get page metrics for full page screenshot:
                # https://chromedevtools.github.io/devtools-protocol/tot/Page/#method-getLayoutMetrics
                raw = {
                    "id": 51,
                    "method": "Page.getLayoutMetrics",
                    "params": {}
                }
                request = json.dumps(raw)
                await websocket.send(request)
                logger.debug("Reading page layout metrics.")
                # Wait for response data:
                while True:
                    response = await websocket.recv()
                    data = json.loads(response)
                    if "id" in data and data["id"] == 51:
                        logger.debug("Page metrics: %dx%d px" % (data["result"]["contentSize"]["width"], data["result"]["contentSize"]["height"]))
                        finalHeight = data["result"]["contentSize"]["height"]
                        break

            # Update viewport with the full page height:
            # https://chromedevtools.github.io/devtools-protocol/1-3/Emulation/#method-setDeviceMetricsOverride
            raw = {
                "id": 52,
                "method": "Emulation.setDeviceMetricsOverride",
                "params": {
                    "width": width,
                    "height": finalHeight,
                    "deviceScaleFactor": 1,  # 1 = 100%
                    "mobile": False,
                    "screenOrientation": {"angle": 0, "type": "portraitPrimary"}
                }
            }
            request = json.dumps(raw)
            await websocket.send(request)
            logger.debug("Viewport updated for full page screenshot.")

            # Disable page domain notifications:
            raw = {
                "id": 60,
                "method": "Page.disable",
                "params": {}
            }
            request = json.dumps(raw)
            await websocket.send(request)
            logger.debug("Page domain notifications disabled.")
            # Wait for the screenshot data:

            # Wait for the user defined screenshot delay:
            if delay > 0:
                logger.info("Waiting %s seconds before taking the screenshot...\n" % delay)
            await asyncio.sleep(delay + 0.5)

            # Take screeshot:
            logger.debug("Taking screenshot.")
            if format == "png" or format == "jpeg":
                # Image file:
                # https://chromedevtools.github.io/devtools-protocol/tot/Page/#method-captureScreenshot
                raw = {
                    "id": 70,
                    "method": "Page.captureScreenshot",
                    "params": {
                        "format": format,  # JPEG or PNG
                        "quality": quality,  # ignored if not JPEG
                        "clip": {
                            "x": left,  # Left offset
                            "y": top,  # Top offset
                            "width": width,  # Screen capture region width
                            "height": finalHeight,  # Screen capture region height
                            "scale": 1  # Scale factor (1 = 100%)
                        }
                    }
                }
                request = json.dumps(raw)
                await websocket.send(request)

            else:
                # PDF file:
                # https://chromedevtools.github.io/devtools-protocol/tot/Page/#method-printToPDF
                # landscape                 boolean     (optional) Paper orientation. Defaults to false.
                # displayHeaderFooter       boolean     (optional) Display header and footer. Defaults to false.
                # printBackground           boolean     (optional) Print background graphics. Defaults to false.
                # scale                     number      (optional) Scale of the webpage rendering. Defaults to 1.
                # paperWidth                number      (optional) Paper width in inches. Defaults to 8.5 inches.
                # paperHeight               number      (optional) Paper height in inches. Defaults to 11 inches.
                # marginTop                 number      (optional) Top margin in inches. Defaults to 1cm (~0.4 inches).
                # marginBottom              number      (optional) Bottom margin in inches. Defaults to 1cm (~0.4 inches).
                # marginLeft                number      (optional) Left margin in inches. Defaults to 1cm (~0.4 inches).
                # marginRight               number      (optional) Right margin in inches. Defaults to 1cm (~0.4 inches).
                # pageRanges                string      (optional) Paper ranges to print, e.g., '1-5, 8, 11-13'. Defaults to the empty string, which means print all pages.
                # ignoreInvalidPageRanges   boolean     (optional) Whether to silently ignore invalid but successfully parsed page ranges, such as '3-2'. Defaults to false.
                # headerTemplate            string      (optional) HTML template for the print header. Should be valid HTML markup with following classes used to inject
                #                                                       printing values into them:
                #                                                       date: formatted print date
                #                                                       title: document title
                #                                                       url: document location
                #                                                       pageNumber: current page number
                #                                                       totalPages: total pages in the document
                #                                                  For example, <span class=title></span> would generate span containing the title.
                #
                # footerTemplate            string      (optional) HTML template for the print footer. Should use the same format as the headerTemplate.
                # preferCSSPageSize         boolean     (optional) Whether or not to prefer page size as defined by css. Defaults to false, in which case the content will be scaled to fit the paper size.
                raw = {
                    "id": 70,
                    "method": "Page.printToPDF",
                    "params": {
                        "printBackground": True
                    }
                }
                request = json.dumps(raw)
                await websocket.send(request)

            # Wait for the screenshot data:
            while True:
                response = await websocket.recv()
                data = json.loads(response)
                if "id" in data and data["id"] == 70:
                    logger.debug("Screenshot ready: %s" % data['id'])
                    break

            # Save screenshot
            try:
                logger.debug("Saving screenshot: %s" % path)
                content = base64.b64decode(data["result"]["data"])
                f = open(path, 'wb')
                f.write(content)
                f.close()
            except Exception as e:
                logger.error(str(e))
                return CHROMX_OUTPUT_FILE_ERROR

            # Unload tab
            response = requests.get("%s:%d/json/close/%s" % (DEVTOOLS_SERVER, DEVTOOLS_PORT, tabID))

    try:
        # Execute screenshot respecting the user defined timeout or default timeout:
        await asyncio.wait_for(main(), timeout=timeout)
        return SHELL_EXECUTION_OK
    # Render timeout:
    except asyncio.TimeoutError:
        # Unload tab
        requests.get("%s:%d/json/close/%s" % (DEVTOOLS_SERVER, DEVTOOLS_PORT, tabID))
        return CHROMX_RENDER_TIMOUT_ERROR
    except websockets.ConnectionClosedError:
        # Unload tab
        requests.get("%s:%d/json/close/%s" % (DEVTOOLS_SERVER, DEVTOOLS_PORT, tabID))
        return CHROMX_CONNECTION_ERROR

def take_screenshot(url_list, options):
    """
        Launch the screenshot workers
        Thanks http://noswap.com/blog/python-multiprocessing-keyboardinterrupt
    """
    global SHELL_EXECUTION_OK, SHELL_EXECUTION_ERROR
    # Stores the Devtools server main websocket URL
    browserControler = None

    screenshot_number = len(url_list)
    print("[+] %s URLs to be screenshot" % screenshot_number)
    
    pool = multiprocessing.Pool(processes=int(options.workers), initializer=init_worker)

    # One browser to control them all \o/...
    if (options.renderer == 'chrome') or (options.renderer == 'chromium'):
        # Execute ChromX in remote debigging mode (Devtools server):
        chromx_debugger_exec(options)
        logger_gen.debug("Waiting for Devtools server to load...")
        while True:
            time.sleep(1)
            response = getWebSocketData()
            if response["code"] == "OK":
                browserControler = response["WS"]
                logger_gen.debug("Devtools server ready.\n")
                break

    taken_screenshots = [
        r for r in pool.imap(
            func=craft_cmd,
            iterable=izip(
                url_list,
                itertools.repeat(options)
            )
        )
    ]

    # Closes Devtools server:
    if (options.renderer == 'chrome') or (options.renderer == 'chromium'):
        asyncio.get_event_loop().run_until_complete(
            chromx_terminate(browserControler)
        )

    pool.close()
    pool.join()

    
    screenshots_error_url = [url for retval, url in taken_screenshots if retval == SHELL_EXECUTION_ERROR]
    screenshots_error = sum(retval == SHELL_EXECUTION_ERROR for retval, url in taken_screenshots)
    screenshots_ok = int(screenshot_number - screenshots_error)
    
    print("[+] %s actual URLs screenshot" % screenshots_ok)
    print("[+] %s error(s)" % screenshots_error)
    
    if screenshots_error != 0:
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