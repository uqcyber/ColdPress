#!/usr/bin/env python3
#
# Copyright (c) 2020,2021 Oracle and/or its affiliates. All rights reserved.
#

from ..modules import NativeModule
import os
from hashlib import md5
import humanhash


'''
module for human hash
'''


# class name has to be capitalized module name
class Humanhash(NativeModule):

    speedType = "fast"
    threaded = True

    # include author info for contact and support
    __author__ = "Haoxi Tan"
    __email__ = "haoxi.tan@gmail.com"
    __description__ = "human hash generation"

    def setup(self,  sample_path, start_path, output_path):
        self.setup_done = False

        self.sample_path = sample_path
        self.start_path = start_path
        self.output_path = output_path

        self.setup_done = True

    def run(self):
        '''
        setup needs to run before this

        '''

        if not self.setup_done:
            print("setup not done, cannot run.")
            return

        self.output = {}
        files = []
        # use a set to remove dups
        hashes = set()
        for root, directories, filenames in os.walk(self.sample_path):
            for filename in filenames:
                filepath = os.path.join(root, filename)
                with open(filepath, 'rb') as f:
                    buf = f.read()
                    digest = md5(buf).hexdigest()
                    hashes.add(humanhash.humanize(digest))
        count = len(hashes)
        self.output['hashes'] = list(hashes)
        print(f"[humanhash] done! generated {count} hashes")

    def get_output(self):
        return self.output
