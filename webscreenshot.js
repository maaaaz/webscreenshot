/***
# This file is part of webscreenshot.
#
# Copyright (C) 2014, 2019 Thomas Debize <tdebize at mail.com>
# All rights reserved.
#
# webscreenshot is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# webscreenshot is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with webscreenshot.	 If not, see <http://www.gnu.org/licenses/>.
***/

var Page = (function(custom_headers, http_username, http_password, image_width, image_height, image_format, image_quality, ajax_timeout, max_timeout, crop_rect, custjs) {
	var opts = {
		width: image_width || 1200,
		height: image_height || 800,
		format: image_format || 'png',
		quality: image_quality || 75,
		cropRect: crop_rect || false,
		ajaxTimeout: ajax_timeout ||1400,
		maxTimeout: max_timeout || 1800,
		httpAuthErrorCode: 2
	};
	
	var requestCount = 0;
	var forceRenderTimeout;
	var ajaxRenderTimeout;

	var page = require('webpage').create();
	page.viewportSize = {
		width: opts.width,
		height: opts.height
	};
	
	if (opts.cropRect) {
		page.clipRect = {
			top: opts.cropRect[0],
			left: opts.cropRect[1],
			width: opts.cropRect[2],
			height: opts.cropRect[3]
		};
	}
	
	page.settings.userAgent = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.90 Safari/537.36';
	page.settings.userName = http_username;
	page.settings.password = http_password;
	
	page.customHeaders = custom_headers;
	
	page.onInitialized = function() {
		page.customHeaders = {};
	};
	// Silence confirmation messages and errors
	page.onConfirm = page.onPrompt = page.onError = noop;

	page.onResourceRequested = function(request) {
		requestCount += 1;
		clearTimeout(ajaxRenderTimeout);
	};

	page.onResourceReceived = function(response) {
		if (response.stage && response.stage == 'end' && response.status == '401') {
			page.failReason = '401';
		}
		
		if (!response.stage || response.stage === 'end') {
			requestCount -= 1;
			if (requestCount === 0) {
				ajaxRenderTimeout = setTimeout(renderAndExit, opts.ajaxTimeout);
			}
		}
	};

	var api = {};

	api.render = function(url, file) {
		opts.file = file;
		
		page.open(url, function(status) {
			if (status !== "success") {
				if (page.failReason && page.failReason == '401') {
					// Specific 401 HTTP code hint
					phantom.exit(opts.httpAuthErrorCode);
				} else {
					// All other failures
					phantom.exit(1);
				}
			} else {
				forceRenderTimeout = setTimeout(renderAndExit, opts.maxTimeout);
			}
		});
	};

	function renderAndExit() {
		// Trick to avoid transparent background
		page.evaluate(function() {
			document.body.bgColor = 'white';
		});
		if (custjs)
		{
			var fs = require('fs');
			var content = fs.read(custjs);
			page.evaluateJavaScript(content);
		}
		page.render(opts.file, {format: opts.format, quality: opts.quality});
		phantom.exit(0);
	}

	function noop() {}

	return api;
});

function main() {
	
	var system = require('system');
	var p_url = new RegExp('url_capture=(.*)');
	var p_outfile = new RegExp('output_file=(.*)');
	var p_header = new RegExp('header=(.*)');
	
	var p_http_username = new RegExp('http_username=(.*)');
	var http_username = '';
	
	var p_http_password = new RegExp('http_password=(.*)');
	var http_password = '';

	var p_width = new RegExp('width=(.*)');
	var image_width = '';
	
	var p_height = new RegExp('height=(.*)');
	var image_height = '';

	var p_format = new RegExp('format=(.*)');
	var image_format = '';

	var p_quality = new RegExp('quality=(.*)');
	var image_quality = '';
	
	var p_ajaxtimeout = new RegExp('ajaxtimeout=(.*)');
	var ajax_timeout = '';

	var p_maxtimeout = new RegExp('maxtimeout=(.*)');
	var max_timeout = '';
	
	var p_crop = new RegExp('crop=(.*)');
	var crop_rect = '';

	var p_custjs = new RegExp('customjs=(.*)');
	var custjs = '';
	
	var temp_custom_headers = {
		// Nullify Accept-Encoding header to disable compression (https://github.com/ariya/phantomjs/issues/10930)
		'Accept-Encoding': ' '
	};
	
	for(var i = 0; i < system.args.length; i++) {
		if (p_url.test(system.args[i]) === true)
		{
			var URL = p_url.exec(system.args[i])[1];
		}
		
		if (p_outfile.test(system.args[i]) === true)
		{
			var output_file = p_outfile.exec(system.args[i])[1];
		}
		
		if (p_http_username.test(system.args[i]) === true)
		{
			http_username = p_http_username.exec(system.args[i])[1];
		}
		
		if (p_http_password.test(system.args[i]) === true)
		{
			http_password = p_http_password.exec(system.args[i])[1];
		}
		
		if (p_header.test(system.args[i]) === true)
		{
			var header = p_header.exec(system.args[i]);		
			var p_header_split = header[1].split(': ', 2);
			var header_name = p_header_split[0];
			var header_value = p_header_split[1];
				
			temp_custom_headers[header_name] = header_value;
			
		}
		
		if (p_width.test(system.args[i]) === true)
		{
			image_width = p_width.exec(system.args[i])[1];
		}
		
		if (p_height.test(system.args[i]) === true)
		{
			image_height = p_height.exec(system.args[i])[1];
		}
		
		if (p_format.test(system.args[i]) === true)
		{
			image_format = p_format.exec(system.args[i])[1];
		}
		
		if (p_quality.test(system.args[i]) === true)
		{
			image_quality = p_quality.exec(system.args[i])[1];
		}
		
		if (p_ajaxtimeout.test(system.args[i]) === true)
		{
			ajax_timeout = p_ajaxtimeout.exec(system.args[i])[1];
		}
		
		if (p_maxtimeout.test(system.args[i]) === true)
		{
			max_timeout = p_maxtimeout.exec(system.args[i])[1];
		}
		
		if (p_crop.test(system.args[i]) === true)
		{
			crop_rect = p_crop.exec(system.args[i])[1].split(',');
		}
		
		if (p_custjs.test(system.args[i]) === true)
		{
			custjs = p_custjs.exec(system.args[i])[1].split(',');
		}
	}
	
	if (typeof(URL) === 'undefined' || URL.length == 0 || typeof(output_file) === 'undefined' || output_file.length == 0) {
		console.log("Usage: phantomjs [options] webscreenshot.js url_capture=<URL> output_file=<output_file.png> [header=<custom header> http_username=<HTTP basic auth username> http_password=<HTTP basic auth password>]");
		console.log('Please specify an URL to capture and an output png filename !');
		
		phantom.exit(1);
	}
	else {
		var page = Page(temp_custom_headers, http_username, http_password, image_width, image_height, image_format, image_quality, ajax_timeout, max_timeout, crop_rect, custjs);
		page.render(URL, output_file);
	}
}

main();