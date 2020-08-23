webscreenshot
=============

Description
-----------
A simple script to screenshot a list of websites, based on the [`url-to-image`](https://github.com/kimmobrunfeldt/url-to-image/) PhantomJS script.

Features
--------
* Integrating url-to-image *'lazy-rendering'* for AJAX resources
* Fully functional on Windows and Linux systems
* Cookie and custom HTTP header definition support for the PhantomJS renderer
* Multiprocessing and killing of unresponding processes after a user-definable timeout
* Accepting several formats as input target
* Customizing screenshot size (width, height), format and quality
* Mapping useful options of PhantomJS such as ignoring ssl error, proxy definition and proxy authentication, HTTP Basic Authentication
* Supports multiple renderers: 
  * **PhantomJS**, which is legacy and [abandoned](https://groups.google.com/forum/#!topic/phantomjs/9aI5d-LDuNE) but the one still producing the best results
  * **Chromium, Chrome and Edge Chromium**, which will replace PhantomJS but currently have some limitations: screenshoting an HTTPS website not having a valid certificate, for instance a self-signed one, will produce an empty screenshot.  
    The reason is that the [`--ignore-certificate-errors`](https://groups.google.com/a/chromium.org/forum/#!topic/headless-dev/eiudRsYdc3A) option doesn't work and will never work anymore: the solution is to use a [proper webdriver](https://bugs.chromium.org/p/chromium/issues/detail?id=697721), but to date `webscreenshot` doesn't aim to support this _rather complex_ method requiring some third-party tools.
  * **Firefox** can also be used as a renderer but has some serious limitations (_so don't use it for the moment_):
    * Impossibility to perform multiple screenshots at the time: no multi-instance of the firefox process
    * No incognito mode, using webscreenshot will pollute your browsing history
* Embedding screenshot URL in image (requires `ImageMagick`) 

Usage
-----
Put your targets in a text file and pass it with the `-i` option, or as a positional argument if you have just a single URL.  
Screenshots will be available, by default, in your current ```./screenshots/``` directory.  
Accepted input formats are the following:
```
http(s)://domain_or_ip:port(/resource)
domain_or_ip:port(/resource)
domain_or_ip(/resource)
```

### Options
```
webscreenshot.py version 2.94

usage: webscreenshot.py [-h] [-i INPUT_FILE] [-o OUTPUT_DIRECTORY] [-w WORKERS] [-v] [--no-error-file] [-z SINGLE_OUTPUT_FILE] [-p PORT] [-s] [-m]
                        [-r {phantomjs,chrome,chromium,edgechromium,firefox}] [--renderer-binary RENDERER_BINARY] [--no-xserver] [--window-size WINDOW_SIZE]
                        [-f {pdf,png,jpg,jpeg,bmp,ppm}] [-q [0-100]] [--ajax-max-timeouts AJAX_MAX_TIMEOUTS] [--crop CROP] [--custom-js CUSTOM_JS] [-l]
                        [--label-size LABEL_SIZE] [--label-bg-color LABEL_BG_COLOR] [--imagemagick-binary IMAGEMAGICK_BINARY] [-c COOKIE] [-a HEADER]
                        [-u HTTP_USERNAME] [-b HTTP_PASSWORD] [-P PROXY] [-A PROXY_AUTH] [-T PROXY_TYPE] [-t TIMEOUT]
                        [URL]

optional arguments:
  -h, --help            show this help message and exit

Main parameters:
  URL                   Single URL target given as a positional argument
  -i INPUT_FILE, --input-file INPUT_FILE
                        <INPUT_FILE> text file containing the target list. Ex: list.txt
  -o OUTPUT_DIRECTORY, --output-directory OUTPUT_DIRECTORY
                        <OUTPUT_DIRECTORY> (optional): screenshots output directory (default './screenshots/')
  -w WORKERS, --workers WORKERS
                        <WORKERS> (optional): number of parallel execution workers (default 4)
  -v, --verbosity       <VERBOSITY> (optional): verbosity level, repeat it to increase the level { -v INFO, -vv DEBUG } (default verbosity ERROR)
  --no-error-file       <NO_ERROR_FILE> (optional): do not write a file with the list of URL of failed screenshots (default false)
  -z SINGLE_OUTPUT_FILE, --single-output-file SINGLE_OUTPUT_FILE
                        <SINGLE_OUTPUT_FILE> (optional): name of a file which will be the single output of all inputs. Ex. test.png

Input processing parameters:
  -p PORT, --port PORT  <PORT> (optional): use the specified port for each target in the input list. Ex: -p 80
  -s, --ssl             <SSL> (optional): enforce SSL/TLS for every connection
  -m, --multiprotocol   <MULTIPROTOCOL> (optional): perform screenshots over HTTP and HTTPS for each target

Screenshot renderer parameters:
  -r {phantomjs,chrome,chromium,edgechromium,firefox}, --renderer {phantomjs,chrome,chromium,edgechromium,firefox}
                        <RENDERER> (optional): renderer to use among 'phantomjs' (legacy but best results), 'chrome', 'chromium', 'edgechromium', 'firefox'
                        (version > 57) (default 'phantomjs')
  --renderer-binary RENDERER_BINARY
                        <RENDERER_BINARY> (optional): path to the renderer executable if it cannot be found in $PATH
  --no-xserver          <NO_X_SERVER> (optional): if you are running without an X server, will use xvfb-run to execute the renderer (by default, trying to
                        detect if DISPLAY environment variable exists

Screenshot image parameters:
  --window-size WINDOW_SIZE
                        <WINDOW_SIZE> (optional): width and height of the screen capture (default '1200,800')
  -f {pdf,png,jpg,jpeg,bmp,ppm}, --format {pdf,png,jpg,jpeg,bmp,ppm}
                        <FORMAT> (optional, phantomjs only): specify an output image file format, "pdf", "png", "jpg", "jpeg", "bmp" or "ppm" (default
                        'png')
  -q [0-100], --quality [0-100]
                        <QUALITY> (optional, phantomjs only): specify the output image quality, an integer between 0 and 100 (default 75)
  --ajax-max-timeouts AJAX_MAX_TIMEOUTS
                        <AJAX_MAX_TIMEOUTS> (optional, phantomjs only): per AJAX request, and max URL timeout in milliseconds (default '1400,1800')
  --crop CROP           <CROP> (optional, phantomjs only): rectangle <t,l,w,h> to crop the screen capture to (default to WINDOW_SIZE: '0,0,w,h'), only
                        numbers, w(idth) and h(eight). Ex. "10,20,w,h"
  --custom-js CUSTOM_JS
                        <CUSTOM_JS> (optional, phantomjs only): path of a file containing JavaScript code to be executed before taking the screenshot. Ex:
                        js.txt

Screenshot label parameters:
  -l, --label           <LABEL> (optional): for each screenshot, create another one displaying inside the target URL (requires imagemagick)
  --label-size LABEL_SIZE
                        <LABEL_SIZE> (optional): font size for the label (default 60)
  --label-bg-color LABEL_BG_COLOR
                        <LABEL_BACKGROUND_COLOR> (optional): label imagemagick background color (default NavajoWhite)
  --imagemagick-binary IMAGEMAGICK_BINARY
                        <LABEL_BINARY> (optional): path to the imagemagick binary (magick or convert) if it cannot be found in $PATH

HTTP parameters:
  -c COOKIE, --cookie COOKIE
                        <COOKIE_STRING> (optional): cookie string to add. Ex: -c "JSESSIONID=1234; YOLO=SWAG"
  -a HEADER, --header HEADER
                        <HEADER> (optional): custom or additional header. Repeat this option for every header. Ex: -a "Host: localhost" -a "Foo: bar"
  -u HTTP_USERNAME, --http-username HTTP_USERNAME
                        <HTTP_USERNAME> (optional): specify a username for HTTP Basic Authentication.
  -b HTTP_PASSWORD, --http-password HTTP_PASSWORD
                        <HTTP_PASSWORD> (optional): specify a password for HTTP Basic Authentication.

Connection parameters:
  -P PROXY, --proxy PROXY
                        <PROXY> (optional): specify a proxy. Ex: -P http://proxy.company.com:8080
  -A PROXY_AUTH, --proxy-auth PROXY_AUTH
                        <PROXY_AUTH> (optional): provides authentication information for the proxy. Ex: -A user:password
  -T PROXY_TYPE, --proxy-type PROXY_TYPE
                        <PROXY_TYPE> (optional): specifies the proxy type, "http" (default), "none" (disable completely), or "socks5". Ex: -T socks
  -t TIMEOUT, --timeout TIMEOUT
                        <TIMEOUT> (optional): renderer execution timeout in seconds (default 30 sec)
```

### Examples
```
list.txt
--------
http://google.fr
https://216.58.213.131
216.58.213.131
https://duckduckgo.com/robots.txt


Default execution with a list
-----------------------------
$ python webscreenshot.py -i list.txt
webscreenshot.py version 2.3

[+] 4 URLs to be screenshot
[+] 4 actual URLs screenshot
[+] 0 error(s)


Default execution with a single URL
-----------------------------------
$ python webscreenshot.py -v google.fr
webscreenshot.py version 2.3

[INFO][General] 'google.fr' has been formatted as 'http://google.fr:80' with supplied overriding options
[+] 1 URLs to be screenshot
[INFO][http://google.fr:80] Screenshot OK

[+] 1 actual URLs screenshot
[+] 0 error(s)


Increasing verbosity level execution
-----------------------------------
$ python webscreenshot.py -i list.txt -v
webscreenshot.py version 2.3

[INFO][General] 'http://google.fr' has been formatted as 'http://google.fr:80' with supplied overriding options
[INFO][General] 'https://216.58.213.131' has been formatted as 'https://216.58.213.131:443' with supplied overriding options
[INFO][General] '216.58.213.131' has been formatted as 'http://216.58.213.131:80' with supplied overriding options
[INFO][General] 'https://duckduckgo.com/robots.txt' has been formatted as 'https://duckduckgo.com:443/robots.txt' with supplied overriding options
[+] 4 URLs to be screenshot
[INFO][https://duckduckgo.com:443/robots.txt] Screenshot OK

[INFO][http://216.58.213.131:80] Screenshot OK

[INFO][https://216.58.213.131:443] Screenshot OK

[INFO][http://google.fr:80] Screenshot OK

[+] 4 actual URLs screenshot
[+] 0 error(s)


Results
-------
$ ls -l screenshots/
total 187
-rwxrwxrwx 1 root root 53805 May 19 16:04 http_216.58.213.131_80.png
-rwxrwxrwx 1 root root 53805 May 19 16:05 http_google.fr_80.png
-rwxrwxrwx 1 root root 53805 May 19 16:04 https_216.58.213.131_443.png
-rwxrwxrwx 1 root root 27864 May 19 16:04 https_duckduckgo.com_443_robots.txt.png
```
  

### Supported options by renderers
Options not listed here below are supported by every current renderer  

| **Option category**   | **Option**                                                                   | **PhantomJS renderer** | **Chromium / Chrome / Edge Chromium renderer** | **Firefox renderer** |
|:---------------------:|------------------------------------------------------------------------------|:----------------------:|:------------------------------:|:--------------------:|
| **Screenshot parameters**   |                                                                              |                        |                                |                      |
|                       | format (`-f`)                                                                  | [**Yes**](https://web.archive.org/web/20200111184123/https://phantomjs.org/api/webpage/method/render.html)                    | No                             | No                   |
|                       | quality (`-q`)                                                                  | [**Yes**](https://web.archive.org/web/20200111184123/https://phantomjs.org/api/webpage/method/render.html)                    | No                             | No                   
|                       | ajax and request timeouts (`--ajax-max-timeouts`)                                         | **Yes**                    | No                             | No                   
|                       | crop (`--crop`)                                                                  | [**Yes**](https://web.archive.org/web/20200111184050/https://phantomjs.org/api/webpage/property/clip-rect.html)                    | No                             | No                   
|                       | custom JavaScript (`--custom-js`)                                                                  | [**Yes**](https://web.archive.org/web/20200823123026/https://phantomjs.org/api/webpage/method/evaluate-java-script.html)                    | No                             | No                   
|                       |                                                                              |                        |                                |                      |
| **HTTP parameters**   |                                                                              |                        |                                |                      |
|                       | cookie (`-c`)                                                                  | **Yes**                    | No                             | No                   |
|                       | header (`-a`)                                                                  | **Yes**                    | No                             | No                   |
|                       | http_username (`-u`)                                                           | **Yes**                    | No                             | No                   |
|                       | http_password (`-b`)                                                           | **Yes**                    | No                             | No                   |
|                       |                                                                              |                        |                                |                      |
| **Connection parameters** |                                                                              |                        |                                |                      |
|                       | proxy (`-P`)                                                                   | **Yes**                    | **Yes**                            | No                   |
|                       | proxy_auth (`-A`)                                                              | **Yes**                    | No                             | No                   |
|                       | proxy_type (`-T`)                                                              | **Yes**                    | [**Yes**](https://github.com/maaaaz/webscreenshot/pull/51)                             | No                   |
|                       |                                                                              |                        |                                |                      |
|                       | Ability to screenshot a HTTPS website with a non-publicly-signed certificate | **Yes**                    | No                             | No                   |
  
  
Requirements
------------
* A Python interpreter with version 2.7 or 3.X
* The webscreenshot python script: 
  * The **easiest way** to setup it: `pip install webscreenshot` and then directly use `$ webscreenshot` 
  * Or git clone that repository and `pip install -r requirements.txt` and then `python webscreenshot.py`
* The PhantomJS tool with at least version 2: follow the [installation guide](https://github.com/maaaaz/webscreenshot/wiki/Phantomjs-installation) and check the [FAQ](https://github.com/maaaaz/webscreenshot/wiki/FAQ) if necessary
* Chrome, Chromium or Firefox > 57 if you want to use one of these renderers
* `xvfb` if you want to run `webscreenshot` in an headless OS: use the `--no-xserver` webscreenshot option to ease everything
* `ImageMagick` binary (`magick` or `convert`) if you want to embed URL in screenshots with the `--label` option: follow the [installation guide](https://github.com/maaaaz/webscreenshot/wiki/ImageMagick-installation)
* Check the [FAQ](https://github.com/maaaaz/webscreenshot/wiki/FAQ) before reporting issues
  

Changelog
---------
* version 2.94 - 08/23/2020: Added custom-js and single output file options
* version 2.93 - 08/16/2020: Added support of Python 3.8 and Microsoft Edge Chromium ; file output for failed webscreenshots ; filename length limitation for long URL 
* version 2.92 - 06/21/2020: no_xserver option autodetection
* version 2.91 - 05/08/2020: Multiprotocol mode fix
* version 2.9 - 01/26/2020: Few fixes
* version 2.8 - 01/11/2020: Few fixes, ajax timeouts + crop + label size + label font options added, default values for ajaxTimeout and maxTimeout changed 
* version 2.7 - 01/04/2020: URL embedding in screenshot option added
* version 2.6 - 12/27/2019: Few fixes
* version 2.5 - 09/22/2019: Image quality and format options added, PhantomJS useragent updated, modern TLD support
* version 2.4 - 05/30/2019: Few fixes for Windows support
* version 2.3 - 05/19/2019: Python 3 compatibility, Firefox renderer added, no-xserver option added
* version 2.2 - 08/13/2018: Chrome and Chromium renderers support and single URL support
* version 2.1 - 01/14/2018: Multiprotocol option addition and PyPI packaging
* version 2.0 - 03/08/2017: Adding proxy-type option
* version 1.9 - 01/10/2017: Using ALL SSL/TLS ciphers
* version 1.8 - 07/05/2015: Option groups definition
* version 1.7 - 06/28/2015: HTTP basic authentication support + loglevel option changed to verbosity
* version 1.6 - 04/23/2015: Transparent background fix
* version 1.5 - 01/11/2015: Cookie and custom HTTP header support
* version 1.4 - 10/12/2014: url-to-image PhantomJS script integration + few bugs corrected
* version 1.3 - 08/05/2014: Windows support + few bugs corrected
* version 1.2 - 04/27/2014: Few bugs corrected
* version 1.1 - 04/21/2014: Changed the script to use PhantomJS instead of the buggy wkhtml binary 
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