#!/usr/bin/env python
# -*- encoding: utf-8 -*-
"""
This is a sample plugin for Angular applications using ui-routing.
It's not going to find everything!
"""
import re

def get_ext():
    return ".js"

def run(filename):
    """
    SpyDir Extension method contains main function to
        process Angular Routes
    """
    req_map = "(url:\s*')(/.*)(')"
    
    route_list = set()

    for line in filename:
        line = line.strip()
        if not line.startswith("//"):
            route = None
            val_find = re.search(req_map, line)
            if val_find:
                if len(val_find.group(2).strip()) > 1:
                    route = "#" + str(val_find.group(2).strip())
            if route is not None:
                route_list.add(route)
    return list(route_list)


def get_name():
    """SpyDir Extension method used to return the name"""
    return "Angular ui-routing"
