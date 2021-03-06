#!/usr/bin/env python3
#
# Copyright (c) 2020,2021 Oracle and/or its affiliates. All rights reserved.
#

from ..modules import NativeModule
import os
from OTXv2 import OTXv2
import IndicatorTypes
from hashlib import md5
import json

'''
module for alienware OTX integration.

you can use this as an example of how to write a external native module
'''


# class name has to be capitalized module name
class Otx(NativeModule):

    speedType = "fast"
    threaded = True

    # include author info for contact and support
    __author__ = "Haoxi Tan"
    __email__ = "haoxi.tan@gmail.com"
    __description__ = "query info about malware hashes on alienware OTX - need OTXv2 python3 module, and otx_apikey in config/apikeys.json in the start path."

    def setup(self,  sample_path, start_path, output_path):
        self.setup_done = False

        self.sample_path = sample_path
        self.start_path = start_path
        self.output_path = output_path

        apikey = None
        with open('config/apikeys.json', 'r') as fp:
            apiconf = json.load(fp)
        apikey = apiconf.get('otx_apikey', None)

        if apikey == None:
            print(
                "OTX api key not found. Did you put it in apikeys.conf in the same directory as run.py?")

        self.otx = OTXv2(apikey)

        self.setup_done = True
        print('[OTX] module setup done!')

    def run(self):
        '''
        setup needs to run before this

        retrieves OTX info about the files in the sample_path, excluding .viv files generated by capa
        stores output in self.output (a dict)
        '''

        # list every file (recursive) in the sample_path, exclude .viv files generated by capa

        if not self.setup_done:
            print("setup not done, cannot run.")
            return

        self.output = {}
        files = []
        # use a set to remove dups
        hashes = set()
        for root, directories, filenames in os.walk(self.sample_path):
            for filename in filenames:
                if root == self.sample_path:
                    if filename.endswith('.viv'):
                        continue
                    filepath = os.path.join(root, filename)
                    with open(filepath, 'rb') as f:
                        buf = f.read()
                        hashes.add(md5(buf).hexdigest())

        count = len(hashes)
        print(f"[OTX] querying {count} hashes")

        for h in hashes:
            deets = self.otx.get_indicator_details_full(
                IndicatorTypes.FILE_HASH_MD5, h)
            #print(f"[OTX] details for f{h}, type {type(deets)}: ", str(deets))
            self.output[h] = deets

        print("OTX done!")

    def get_output(self):
        print('[OTX] get_output: ', str(self.output)[:50], '...')
        # print(self.output)
        return self.output
