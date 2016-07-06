# SpyDir
The purpose of the SpyDir tool is to extend the functionality of the BurpSuite Proxy by automating Forced Browsing. The tool attempts to enumerate application endpoints via an input directory containing the application's source code. The tool provides an option to process files as endpoints, think: ASP, PHP, HTML, or parse files to attempt to enumerate endpoints via plugins, think: MVC. Users may opt to send the discovered endpoints directly to the Burp Spider.  

## Plugins
Currently plugins need to live in a directory titled, "plugins" next to the BurpSuite jar file. Plugin requirements:

* Have a get_name() function that returns a string with the title of the plugin. 
* Have a run() function that accepts a string filename. Return a list, [], of endpoints. 

## Requirements
Jython2.7+ stand-alone jar file. Get it here: http://www.jython.org/downloads.html

## TODO
1. Modify the plugin return type to allow the specification of HTTP method passed to the spider.
2. Allow the user to move the plugins to a specified location
3. Allow reloading of plugins without reloading the extension.
4. Research possibility of implementing a brute-force mechanism based on language/framework. This tool may feed such a mechanism by remembering previously identified endpoints.
5. Potentially expand the compare SiteMap feature currently included... or scrap it. TBD.
6. Add context menus to send the relevant information from the Target/Proxy/etc. tabs to the extension.