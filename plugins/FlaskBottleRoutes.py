#!/usr/bin/env python
# -*- encoding: utf-8 -*-
import re
from random import randint

# Define on a per app basis: dictionary of {var_name: str(type)}
#PATH_VARS = {'unknown': 'int'}
PATH_VARS = {'<username>': 'str'}


def handle_path_vars(var_names):
    """
    Handles the path vars found during run
    Returns dict of {var_name: 'random' value}
    """
    ret_val = {}
    for var in var_names:
        if var in PATH_VARS.keys():
            if PATH_VARS[var] == "int":
                ret_val[var] = randint(0, 47)
            elif PATH_VARS[var] == 'str':
                ret_val[var] = "test"
            # Define more based on need
            else:
                ret_val[var] = ""
    return ret_val

def get_ext():
    """Defines the extension type expected within SpyDir"""
    return ".py"

def run(filename):
    """
    SpyDir Extension method contains main function to
        process Flask/Bottle Routes
    """
    route_rule = r"""^@*(app\.route\(|^bottle\.route\(|route\()"""
    path_rule = r"(<\w+>)"
    route_list = []

    for line in filename:
        line = line.replace("'", '"').replace('"', "").strip()
        if re.search(route_rule, line):
            if "methods" in line:  # this is ignored currently
                methods = line.split("[")[1].split("]")[0].split(",")
            line = re.split(route_rule, line)[2].split(")")[0].split(',')[0]
            if re.search(path_rule, line):
                path_values = handle_path_vars(re.findall(path_rule, line))
                for k, v in path_values.items():
                    line = line.replace(k, str(v))
            route_list.append(line)
    return route_list


def get_name():
    """SpyDir Extension method used to return the name"""
    return "Flask/Bottle Routes"
