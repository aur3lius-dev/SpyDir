#!/usr/bin/env python
# -*- encoding: utf-8 -*-
"""
This is a sample plugin for ASP.NET MVC applications.
It's not going to find everything!
"""
import re
from random import randint


class Status():
    """Sample class to parse HTTP method"""
    def __init__(self):
        """Init"""
        self.last_lines = []
        self.handle_method = False

    def handle_http_method(self):
        """find http method"""
        http_meth = ""
        if self.handle_method:
            for prev_line in self.last_lines:
                if "HttpPost" in prev_line:
                    http_meth = "POST"
                    break
                else:
                    http_meth = "GET"
        return http_meth


def param_parse(params):
    """
    Function to parse and provide random values for parameters of ActionResults
    Only handles certain builtin types within ASP.NET MVC!
    Returns a dictionary of parameter name and the "generated" value
    """
    results = {}
    for p in params.split(','):
        if '?' in p:
            p = p.replace('?', '')
        if 'bool' in p:
            pname = p.split('bool')[1]
            val = "false"
        elif 'sbyte' in p:
            pname = p.split('sbyte')[1]
            val = '123'
        elif 'int' in p:
            pname = p.split('int ')[1]
            val = randint(-2147483648, 2147483647)
        elif 'string' in p:
            pname = p.split('string ')[1]
            val = ""
        else:
            pname = p.split()[1]
            val = ""
        if '=' in pname:
            pname = pname.split('=')[0].strip()
        pname = pname.strip()
        results[pname] = val

    return results

def get_ext():
    """returns the extensions associated with this plugin"""
    return ".cs"

def run(filename):
    """
    MUST HAVE FUNCTION!
    Begins the plugin processing
    Returns a list of endpoints
    """
    run_results = []
    url = None
    cont = None
    # location isn't currently used
    location = ""
    prog = re.compile(r"((\s:\s){1}(.)*Controller)", flags=re.IGNORECASE)
    stats = Status()

    for line in filename:
        try:
            if prog.search(line):
                cont = line.split("Controller")[0].split("class ")[1]
            if cont:
                stats.last_lines.append(line)
            if " ActionResult " in line and cont:
                params = line.split("(")[1].split(")")[0]
                action_point = line.split("ActionResult ")[1].split("(")[0]
                http_meth = stats.handle_http_method()
                if params:
                    p_string = "?"
                    for k, v in param_parse(params).items():
                        p_string += '%s=%s&' % (k, v)
                    url = "%s/%s/%s%s\t%s" % (location,
                                              cont, action_point,
                                              p_string[:-1], http_meth)
                else:
                    url = "%s/%s/%s\t%s" % (location,
                                            cont, action_point, http_meth)
            if url is not None:
                run_results.append(url.strip())
                url = None
        except Exception as e:
            # Print the offending line the BurpSuite's extension Output tab
            print("Error! Couldn't parse: %s" % line)
    return run_results


def get_name():
    """MUST HAVE FUNCTION! Returns plugin name."""
    return "ASP.NET MVC"
