#!/usr/bin/env python
# -*- encoding: utf-8 -*-
import re
from sys import argv
from os import walk, path
from random import randint

# Define on a per app basis: dictionary of {var_name: str(type)}
PATH_VARS = {'uid': 'int', 'aid': 'int', 'pid': 'int'}

def handle_path_vars(var_names):
    """
    Handles the path vars found during run
    Returns dict of {var_name: 'random' value}
    """
    ret_val = {}
    for var in var_names:
        var = var.strip("<").strip(">")
        if var in PATH_VARS.keys():
            if PATH_VARS[var] == "int":
                ret_val[var] = randint(0, 47)
            # Define more based on need
    return ret_val

def run(filename):
    """SpyDir Extension method contains main function to process Flask Routes"""
    route_rule = "@app.route"
    path_rule = "(<\w+>)"
    route_list = []
    
    for line in filename:
        line = line.replace("'", '"').replace('"', "")
        if re.search(route_rule, line):
            if "methods" in line:  # this is ignored currently
                methods = line.split("[")[1].split("]")[0].split(",")
            line = line.split(route_rule + "(")[1].split(")")[0].split(',')[0]
            if re.search(path_rule, line):
                path_values = handle_path_vars(re.findall(path_rule, line))
                line = line.replace("<", "").replace(">", "")
                for k,v in path_values.items():
                    print(k,v)
                    line = line.replace(k, str(v))
            route_list.append(line)
    return route_list

def get_name():
    """SpyDir Extension method used to return the name"""
    return "Flask Routes"
