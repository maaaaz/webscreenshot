webscreenshot
=============

Description
-----------
A simple script to screenshot a list of websites, based on the [`url-to-image`](https://github.com/kimmobrunfeldt/url-to-image/) phantomjs script.

Features
--------
* Integrating url-to-image 'lazy-rendering' for AJAX resources
* Fully functional on Windows and Linux systems
* Cookie and custom HTTP header definition support
* Multiprocessing and killing of unresponding processes after a user-definable timeout
* Accepts several format as input target
* Maps useful options of phantomjs such as ignoring ssl error, proxy definition and proxy authentication, HTTP Basic Authentication

Usage
-----
Put your targets in a text file and pass it to the script (`-i`).  
Screenshots will be available in your current ```./screenshots/``` directory (default).  
Accepted input formats are the following:
```
http(s)://domain_or_ip:port(/ressource)
domain_or_ip:port(/ressource)
domain_or_ip(/ressource)
```

### Options
```
$ python webscreenshot.py -h
Usage: webscreenshot.py [options]

Options:
  -h, --help            show this help message and exit

  Main parameters:
    -i INPUT_FILE, --input-file=INPUT_FILE
                        <INPUT_FILE>: text file containing the target list.
                        Ex: list.txt
    -o OUTPUT_DIRECTORY, --output-directory=OUTPUT_DIRECTORY
                        <OUTPUT_DIRECTORY> (optional): screenshots output
                        directory (default './screenshots/')
    -w WORKERS, --workers=WORKERS
                        <WORKERS> (optional): number of parallel execution
                        workers (default 2)
    -v, --verbosity     <VERBOSITY> (optional): verbosity level, repeat it to
                        increase the level { -v INFO, -vv DEBUG } (default
                        verbosity ERROR)

  Input processing parameters:
    -p PORT, --port=PORT
                        <PORT> (optional): use the specified port for each
                        target in the input list. Ex: -p 80
    -s, --ssl           <SSL> (optional): enforce ssl for every connection
    -m, --multiprotocol
                        <MULTIPROTOCOL> (optional): perform screenshots over
                        HTTP and HTTPS for each target

  HTTP parameters:
    -c COOKIE, --cookie=COOKIE
                        <COOKIE_STRING> (optional): cookie string to add. Ex:
                        -c "JSESSIONID=1234; YOLO=SWAG"
    -a HEADER, --header=HEADER
                        <HEADER> (optional): custom or additional header.
                        Repeat this option for every header. Ex: -a "Host:
                        localhost" -a "Foo: bar"
    -u HTTP_USERNAME, --http-username=HTTP_USERNAME
                        <HTTP_USERNAME> (optional): specify a username for
                        HTTP Basic Authentication.
    -b HTTP_PASSWORD, --http-password=HTTP_PASSWORD
                        <HTTP_PASSWORD> (optional): specify a password for
                        HTTP Basic Authentication.

  Connection parameters:
    -P PROXY, --proxy=PROXY
                        <PROXY> (optional): specify a proxy. Ex: -P
                        http://proxy.company.com:8080
    -A PROXY_AUTH, --proxy-auth=PROXY_AUTH
                        <PROXY_AUTH> (optional): provides authentication
                        information for the proxy. Ex: -A user:password
    -T PROXY_TYPE, --proxy-type=PROXY_TYPE
                        <PROXY_TYPE> (optional): specifies the proxy type,
                        "http" (default), "none" (disable completely), or
                        "socks5". Ex: -T socks
    -t TIMEOUT, --timeout=TIMEOUT
                        <TIMEOUT> (optional): phantomjs execution timeout in
                        seconds (default 30 sec)

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

[+] 4 URLs to be screenshot
[+] 4 actual URLs screenshot
[+] 0 errors


Increasing verbosity level execution
-----------------------------------
$ python webscreenshot.py -i list.txt -v
webscreenshot.py version 1.1

[INFO][General] 'http://google.fr' has been formatted as 'http://google.fr:80' with supplied overriding options
[INFO][General] 'https://173.194.67.113' has been formatted as 'https://173.194.67.113:443' with supplied overriding options
[INFO][General] '173.194.67.113' has been formatted as 'http://173.194.67.113:80' with supplied overriding options
[INFO][General] 'https://duckduckgo.com/robots.txt' has been formatted as 'https://duckduckgo.com:443/robots.txt' with supplied overriding options
[+] 4 URLs to be screenshot
[INFO][http://173.194.67.113:80] Screenshot OK
[INFO][https://173.194.67.113:443] Screenshot OK
[INFO][http://google.fr:80] Screenshot OK
[INFO][https://duckduckgo.com:443/robots.txt] Screenshot OK
[+] 4 actual URLs screenshot
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
* Python 2.7
* webscreenshot python script: 
  * The **easiest way** to setup it: `pip install webscreenshot` and then directly use `$ webscreenshot` 
  * Or git clone that repository
* Phantomjs > 2.x : follow the [installation guide](https://github.com/maaaaz/webscreenshot/wiki/Phantomjs-installation) and check the [FAQ](https://github.com/maaaaz/webscreenshot/wiki/FAQ) if necessary


Changelog
---------
* version 2.1 - 01/14/2018: Multiprotocol option addition and PyPI packaging
* version 2.0 - 03/08/2017: Adding proxy-type option
* version 1.9 - 01/10/2017: Using ALL SSL/TLS ciphers
* version 1.8 - 07/05/2015: Option groups definition
* version 1.7 - 06/28/2015: HTTP basic authentication support + loglevel option changed to verbosity
* version 1.6 - 04/23/2015: Transparent background fix
* version 1.5 - 01/11/2015: Cookie and custom HTTP header support
* version 1.4 - 10/12/2014: url-to-image phantomjs script integration + few bugs corrected
* version 1.3 - 08/05/2014: Windows support + few bugs corrected
* version 1.2 - 04/27/2014: few bugs corrected
* version 1.1 - 04/21/2014: Changed the script to use phantomjs instead of the buggy wkhtml binary 
* version 1.0 - 01/12/2014: Initial commit

Copyright and license
---------------------
webscreenshot is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

webscreenshot is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  

See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with webscreenshot. 
If not, see http://www.gnu.org/licenses/.

Contact
-------
* Thomas Debize < tdebize at mail d0t com >