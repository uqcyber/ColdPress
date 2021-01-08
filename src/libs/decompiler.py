#!/usr/bin/env python
#
# Copyright (c) 2019 Allsafe
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#

from ghidra.app.decompiler import DecompInterface

# `currentProgram` or `getScriptArgs` function is contained in `__main__`
# actually you don't need to import by yourself, but it makes much "explicit"
import __main__ as ghidra_app


class Decompiler:
    '''decompile binary into psuedo c using Ghidra API.
    Usage:
        >>> decompiler = Decompiler()
        >>> psuedo_c = decompiler.decompile()
        >>> # then write to file
    '''

    def __init__(self, program=None, timeout=None):
        '''init Decompiler class.
        Args:
            program (ghidra.program.model.listing.Program): target program to decompile, 
                default is `currentProgram`.
            timeout (ghidra.util.task.TaskMonitor): timeout for DecompInterface::decompileFunction
        '''

        # initialize decompiler with current program
        self._decompiler = DecompInterface()
        self._decompiler.openProgram(program or ghidra_app.currentProgram)

        self._timeout = timeout
    
    def decompile_func(self, func):
        '''decompile one function.
        Args:
            func (ghidra.program.model.listing.Function): function to be decompiled
        Returns:
            string: decompiled psuedo C code
        '''

        # decompile
        dec_status = self._decompiler.decompileFunction(func, 0, self._timeout)
        # check if it's successfully decompiled
        if dec_status and dec_status.decompileCompleted():
            # get psuedo c code
            dec_ret = dec_status.getDecompiledFunction()
            if dec_ret:
                return dec_ret.getC()

    def decompile(self):
        '''decompile all function recognized by Ghidra.
        Returns:
            string: decompiled all function as psuedo C
        '''

        # all decompiled result will be joined
        psuedo_c = ''

        # enum all functions and decompile each function
        funcs = ghidra_app.currentProgram.getListing().getFunctions(True)
        for func in funcs:
            dec_func = self.decompile_func(func)
            if dec_func:
                psuedo_c += dec_func

        return psuedo_c


def run():

    # getScriptArgs gets argument for this python script using `analyzeHeadless`
    args = ghidra_app.getScriptArgs()
    if len(args) > 1:
        print('[!] wrong parameters, see following\n\
Usage: ./analyzeHeadless <PATH_TO_GHIDRA_PROJECT> <PROJECT_NAME> \
-process|-import <TARGET_FILE> [-scriptPath <PATH_TO_SCRIPT_DIR>] \
-postScript|-preScript decompile.py <PATH_TO_OUTPUT_FILE>')
        return
    
    # if no output path given, 
    # <CURRENT_PROGRAM>_decompiled.c will be saved in current dir
    if len(args) == 0:
        cur_program_name = ghidra_app.currentProgram.getName()
        output = '{}_decompiled.c'.format(''.join(cur_program_name.split('.')[:-1]))
    else:
        output = args[0]

    # do decompile
    decompiler = Decompiler()
    psuedo_c = decompiler.decompile()

    # save to file, wb because there might be non-unicode symbols
    with open(output, 'wb') as fw:
        fw.write(psuedo_c.encode('utf-8'))
        print('[*] success. save to -> {}'.format(output))


# it will be ran form here
if __name__ == '__main__':
    run()
