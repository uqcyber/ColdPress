#!/usr/bin/env python3
#
# Copyright (c) 2020, Oracle and/or its affiliates. All rights reserved.
#

from ..modules import CmdModule
import os

'''
module for (a slightly modified) yarGen to generate yara rules for a malware 
sample.

also the first external module in coldpress, which can be used as an example 
of how to create a command line module.
'''



# class name has to be capitalized module name
class Yargen(CmdModule):

    speedType = "slow"
    threaded = True


    # include author info for contact and support
    __author__ = "Haoxi Tan"
    __email__  = "haoxi.tan@gmail.com"
    __description__ = "generate yara rules with yarGen.py tool https://github.com/Neo23x0/yarGen"



    def setup(self, sample_path, start_path, output_path):
        self.setup_done = False

        self.sample_path = sample_path
        self.start_path = start_path
        self.output_path = output_path

        self.setup_done = True

    def get_cmd(self):
        '''
        returns the cmd to run
        '''

        if not self.setup_done:
            print("setup not done, cannot run.")
            raise Exception('[%s] setup not done, cannot run' % self.__class__.__name__)
            return 

        print("[yargen] get_cmd called")
        outfile = f"yaraRules.yara"
        # no recurse; because it will make it very slow
        return f"python {self.start_path}/yarGen/yarGen.py -m {self.sample_path} --nr -o {os.path.join(self.output_path,outfile)}"

