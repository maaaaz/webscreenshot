/***
# This file is part of webscreenshot.
#
# Copyright (C) 2014, Thomas Debize <tdebize at mail.com>
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
**/

var system = require('system');
var page = require('webpage').create();
var p_url = new RegExp('url_capture=(.*)');
var p_outfile = new RegExp('output_file=(.*)');

for(var i = 0; i < system.args.length; i++) {
	if (p_url.test(system.args[i]) === true)
	{
		var URL = p_url.exec(system.args[i])[1];
	}
	
	if (p_outfile.test(system.args[i]) === true)
	{
		var output_file = p_outfile.exec(system.args[i])[1];
	}
}

if (typeof(URL) === 'undefined' || URL.length == 0 || typeof(output_file) === 'undefined' || output_file.length == 0) {
	console.log("Usage: phantomjs [options] webscreenshot.js url_capture=<URL> output_file=<output_file.png>");
	console.log('Please specify an URL to capture and an output png filename !');
	phantom.exit(1);
} 
else {
	page.open(URL, function() {
		page.render(output_file);
		phantom.exit(0);
	});
}