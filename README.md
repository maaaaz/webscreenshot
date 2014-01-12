webscreenshot
=============

Description
-----------
A simple script to screenshot a list of websites, based on wkhtmltoimage binary.

Features
--------
* Multiprocessing and kill of unresponding processes after a user-definable timeout
* Accepts several format as input target
* Maps most used options of wkhtmltoimage such as proxy, http authentication and cookie

Usage
-----
Make a list including your targets and pass it to the script (-i). Screenshots will be available in your current './screeshots' directory.
Accepted input formats are the following:
```
http(s)://domain_or_ip:port(/ressource)
domain_or_ip:port(/ressource)
domain_or_ip(/ressource)
```

See options for advanced usage
### Options
```
$ python webscreenshot.py -h
Usage: webscreenshot.py [options]

Options:
  -h, --help            show this help message and exit
  -i INPUT_FILE, --input-file=INPUT_FILE
                        <INPUT_FILE>: text file containing the target list.
                        Ex: list.txt
  -o OUTPUT_DIRECTORY, --output-directory=OUTPUT_DIRECTORY
                        <OUTPUT_DIRECTORY>: screenshots output directory
                        (default './screenshots/')
  -u USERNAME, --username=USERNAME
                        <USERNAME>: HTTP Authentication username
  -m PASSWORD, --password=PASSWORD
                        <PASSWORD>: HTTP Authentication password
  -P PROXY, --proxy=PROXY
                        <PROXY>: Specify a proxy. Ex: -P
                        http://user:password@myproxyserver:8080 -P
                        socks5://myproxyserver
  -c COOKIE, --cookie=COOKIE
                        <COOKIE>: Specify a cookie string to use. Ex: -c
                        "foo=bar" -c "foo1=bar1;foo2=bar2"
  -p PORT, --port=PORT  <PORT>: use the specified port for each target in the
                        input list. Ex: -p 80
  -s, --ssl             <SSL>: enforce ssl for every connection
  -t TIMEOUT, --timeout=TIMEOUT
                        <TIMEOUT>: wkhtml execution timeout in seconds
                        (default 30 sec)
  -w WORKERS, --workers=WORKERS
                        <WORKERS>: number of parallel execution workers
                        (default 3)
  -l LOG_LEVEL, --log-level=LOG_LEVEL
                        <LOG_LEVEL> verbosity level { DEBUG, INFO, WARN,
                        ERROR, CRITICAL } (default ERROR)
```

### Examples
```
list.txt
--------
http://google.fr
https://173.194.67.113
173.194.67.113
https://duckduckgo.com/robots.txt

Default execution
-----------------
$ python webscreenshot.py -i list.txt
webscreenshot.py version 1.0

[+] 4 URLs to be screenshotted
[+] 4 actual URLs screenshotted
[+] 0 errors

Increased verbosity level execution
-----------------------------------
$ python webscreenshot.py -i list.txt -l INFO
webscreenshot.py version 1.0

[INFO][General] 'http://google.fr' has been formated as 'http://google.fr:80' with supplied overriding options
[INFO][General] 'https://173.194.67.113' has been formated as 'https://173.194.67.113:443' with supplied overriding options
[INFO][General] '173.194.67.113' has been formated as 'http://173.194.67.113:80' with supplied overriding options
[INFO][General] 'https://duckduckgo.com/robots.txt' has been formated as 'https://duckduckgo.com:443/robots.txt' with supplied overriding options
[+] 4 URLs to be screenshotted
[INFO][http://173.194.67.113:80] Screenshot OK
[INFO][https://173.194.67.113:443] Screenshot OK
[INFO][http://google.fr:80] Screenshot OK
[INFO][https://duckduckgo.com:443/robots.txt] Screenshot OK
[+] 4 actual URLs screenshotted
[+] 0 errors

Results
-------
$ ls -l screenshots/
total 61
-rwxrwxrwx 1 root root 35005 Jan 12 19:46 http___173.194.67.113_80.png
-rwxrwxrwx 1 root root 38152 Jan 12 19:46 http___google.fr_80.png
-rwxrwxrwx 1 root root 35005 Jan 12 19:46 https___173.194.67.113_443.png
-rwxrwxrwx 1 root root 12828 Jan 12 19:46 https___duckduckgo.com_443_robots.txt.png
```

Requirements
------------
* python >= 2.6
* wkhtmltoimage binary (included)

Changelog
---------
* version 1.0 - 01/12/2014: Initial commit

Copyright and license
---------------------
webscreenshot is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

webscreenshot is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  

See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with webscreenshot. 
If not, see http://www.gnu.org/licenses/.

wkhtmltoimage is also distributed under LGPL : https://code.google.com/p/wkhtmltopdf/

Contact
-------
* Thomas Debize < tdebize at mail d0t com >