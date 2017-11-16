#!/usr/bin/env python
# -*- encoding: utf-8 -*-
"""
This is a sample plugin for Angular applications using ui-routing.
Now handles some React router cases too! Yay efficiency!
It's not going to find everything!
"""
import re

def get_ext():
    """Returns the file extensions associated with this plugin"""
    return ".js"

def run(filename):
    """
    SpyDir Extension method contains main function to
        process Angular and React Routes
    """
    ang_str = re.compile(r"(url:\s*')(/.*)(')")
    react_str = re.compile(r"(Route[\s]+path[\s]?=['\"])([^'\"\s]+)(['\"]+)")
    route_list = set()

    for line in filename:
        line = line.strip()
        if not line.startswith("//"): # Avoid commented lines. We want the real thing.
            route = None
            ang_find = ang_str.search(line)
            react_find = react_str.search(line)
            if ang_find:
                route = ret_route(ang_find)
            elif react_find:
                route = ret_route(react_find)
            if route is not None:
                route_list.add(route)
    return list(route_list)

def ret_route(found):
    """returns the route for both rules"""
    if len(found.group(2).strip()) > 1:
        return "#" + str(found.group(2).strip())



def get_name():
    """SpyDir Extension method used to return the name"""
    return "Angular/React Routing"
