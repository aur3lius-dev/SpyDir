# SpyDir
The purpose of the SpyDir tool is to extend the functionality of BurpSuite Proxy by automating Forced Browsing. The tool attempts to enumerate application endpoints via an input directory containing the application's source code. The tool provides an option to process files as endpoints, think: ASP, PHP, HTML, or parse files to attempt to enumerate endpoints via plugins, think: MVC. Users may opt to send the discovered endpoints directly to the Burp Spider.  

## Plugins
Plugin requirements:

* Have a get_name() function that returns a string with the title of the plugin. 
* Have a run() function that accepts a string filename. Return a list, [], of endpoints. 

## Requirements
Jython2.7+ stand-alone jar file. Get it here: http://www.jython.org/downloads.html

## TODO
1. Modify the plugin return type to allow the specification of HTTP method passed to the spider. (This will require a custom HTTP request and handler)
2. Research possibility of implementing a brute-force mechanism based on language/framework. This tool may feed such a mechanism by remembering previously identified endpoints.
3. Add context menus to send the relevant information from the Target/Proxy/etc. tabs to the extension.