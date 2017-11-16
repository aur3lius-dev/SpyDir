#!/usr/bin/env python
# -*- encoding: utf-8 -*-
"""
This is a sample plugin for ASP.NET MVC applications.
It's not going to find everything!
"""
import re

def get_ext():
    """Returns the ext associated with this plugin"""
    return ".cs"

def run(filename):
    """
    MUST HAVE FUNCTION!
    Begins the plugin processing
    Returns a list of endpoints
    """
    run_results = set()
    r_rule = re.compile(r"(Route\(\"[^,)]+)", flags=re.IGNORECASE)

    for line in filename:
        try:
            route_match = r_rule.search(line)
            if route_match:
                run_results.add(route_match.group(1)[7:-1])
        except Exception:
            # Print the offending line the BurpSuite's extension Output tab
            print("Error! Couldn't parse: %s" % line)
    return list(run_results)


def get_name():
    """MUST HAVE FUNCTION! Returns plugin name."""
    return "C# Route"
