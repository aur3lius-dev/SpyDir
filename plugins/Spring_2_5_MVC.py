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


def set_param_vals():
    return {
        "{String}": "str12345",
        "{int}": 12345,
        "{Long}": 9012310231013
    }

def handle_params(params):
    assignment = ""
    reg = re.compile('(.*?"\))([\s])(.*?)(,|\))')
    for par in params:
        par_find = reg.search(par)
        if par_find:
            par_name = par_find.group(1).replace('"', "").replace(")", "")
            par_type = par_find.group(3).split()[0].strip()
            assignment += "%s={%s}&" % (par_name, par_type)
    for k, v in set_param_vals().items():
        assignment = assignment.replace(k, str(v))
    return assignment[:-1]


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
    route_rule = re.compile("(value\s*=\s*[{]?)([\"].*[\"])(,|\))|([\"].*[\"])")
    path_rule = re.compile("({\w+})")
    req_param = "@RequestParam(\""

    route_list = []

    for line in filename:
        line = line.strip()
        if not line.startswith("//"):
            route = None
            if req_map in line:
                line = line.replace(req_map, "").replace(")", "")
                val_find = route_rule.search(line)
                if val_find:
                    if val_find.group(2) is not None:
                        route = val_find.group(2).replace(
                            "\"", "").strip().split(',')[0]
                    elif val_find.group(4) is not None:
                        route = val_find.group(4).replace("\"", "").strip()
                        if ',' in val_find.group(4):
                            for r in val_find.group(4).split(','):
                                r = r.strip().replace('"', '')
                                route_list.append(r)
                            route = r
                if route is not None:
                    path_finder = path_rule.search(route)
                    if path_finder:
                        route = handle_path_vars(route)
                    route_list.append(route)
                    prev_route = route
            if req_param in line:
                params = line.split(req_param)
                w_pars = "%s?%s" % (prev_route, handle_params(params[1:]))
                route_list.append(w_pars)

            # Don't currently process methods at the extension level
            # mult_method = re.search("([,\s*|)\s*]method\s*=\s*\{.*\})", line)
            # if mult_method:
            #    mult_method = mult_method.group().strip()
    route_list.sort()
    return route_list


def get_name():
    """SpyDir Extension method used to return the name"""
    return "Spring 2.5+ MVC"
