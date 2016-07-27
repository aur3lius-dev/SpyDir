#!/usr/bin/env python
# -*- encoding: utf-8 -*-
"""
This is a sample plugin for Spring Framework 2.5+ MVC applications.
It's not going to find everything!
"""
import re


def set_path_vars():
    """Update these variables and values on a per app basis."""
    return {
            "{id}": 2,
            "{eventId}": 3,
            "{receiver}": "Steve",
            "{user}": "Bob",
            "{userId}": 4,
            "{friend}": "Paul",
            "{owner}": "Tom",
            "{name}": "John",
            "{amount}": "3.50",
            "{hidden}": "secret",
            "{oldPassword}": "12345",
            "{newPassword}": "hunter2"}


def handle_path_vars(route):
    """
    Replaces the placeholder variables with values from set_path_vars()
    Returns a string containing the updated route
    """
    new_route = route
    for k, v in set_path_vars().items():
        new_route = new_route.replace(k, str(v))
    return new_route

def get_ext():
    return ".java"

def run(filename):
    """
    SpyDir Extension method contains main function to
        process Spring 2.5+ MVC Routes
    """
    req_map = "@RequestMapping("
    route_rule = "(value\s*=\s*)([\"].*[\"])|([\"].*[\"])"
    path_rule = "({\w+})"
    route_list = []
    for line in filename:
        if not line.startswith("//"):
            route = None
            line = line.strip()
            if req_map in line:
                line = line.replace(req_map, "").replace(")", "")
                val_find = re.search(route_rule, line)
                if val_find:
                    if val_find.group(2) is not None:
                        route = val_find.group(2).replace("\"", "").strip()
                    elif val_find.group(3) is not None:
                        route = val_find.group(3).replace("\"", "").strip()
                if route is not None:
                    path_finder = re.search(path_rule, route)
                    if path_finder:
                        route = handle_path_vars(route)
                    route_list.append(route)
            # Don't currently process methods at the extension level
            # mult_method = re.search("([,\s*|)\s*]method\s*=\s*\{.*\})", line)
            # if mult_method:
            #    mult_method = mult_method.group().strip()
    return route_list


def get_name():
    """SpyDir Extension method used to return the name"""
    return "Spring 2.5+ MVC"
