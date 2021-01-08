#!/usr/bin/env python3
#
# Copyright (c) 2020,2021 Oracle and/or its affiliates. All rights reserved.
#

'''
loader functions for loading external modules

WARNING: be very careful if you want to modify this magic!!! 

'''

#                                                / \/ \
#                                               (/ //_ \_
#      .-._                                      \||  .  \
#       \  '-._                            _,:__.-"/---\_ \
#  ______/___  '.    .--------------------'~-'--.)__( , )\ \
# `'--.___  _\  /    |             Here        ,'    \)|\ `\|
#      /_.-' _\ \ _:,_          Be Dragons           " ||   (
#    .'__ _.' \'-/,`-~`                                |/
#        '. ___.> /=,|  Abandon hope all ye who enter  |
#         / .-'/_ )  '---------------------------------'
#         )'  ( /(/
#              \\ "
#               '=='


import os
import importlib


def load_all():
    '''
    load all modules in this directory 

    folder structure:
    .
        loader.py
        modules.py
        ... other python files
        ------------------------- the above are ignored
        foo/
            foo_module.py       <-----|
        bar/                  |
            bar_module.py       <-----|
                                  |
        ^^^^^^^^^^^^^^^^^^^^^^^^ these are loaded!

    returns initiated module objects
    '''

    mods = []

    for root, dirs, files in os.walk('modules'):

        if root != '.':  # ignore current directory
            for f in files:
                if len(root.lstrip('./').split(os.path.sep)) == 2:
                    module_dirname = root.lstrip(
                        './').split(os.path.sep)[1]  # .replace('/','.')
                else:
                    continue
                print("loader dirname:", module_dirname)
                if f == f"{module_dirname}_module.py":  # <--- load this!

                    # print("loader modname:", modname)
                    classname = module_dirname.capitalize()
                    modname = root.lstrip('./').replace('/', '.')
                    print(
                        f"classname: {classname}, to import: {modname}.{module_dirname}_module")
                    m = importlib.import_module(
                        f"{modname}.{module_dirname}_module")
                    class_ = getattr(m, classname)
                    instance = class_()
                    print(f"loaded {classname}")

                    mods.append(instance)

    print("all loaded modules:", mods)
    return mods


if __name__ == "__main__":
    load_all("test", "test_start")
