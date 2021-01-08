#!/usr/bin/env python3
#
# Copyright (c) 2020, Oracle and/or its affiliates. All rights reserved.
#

from ..modules import NativeModule
import os
import vt
from hashlib import sha1
import json

'''
module for virustotal threat intel integration. used to look up a hash and
return lots of information

need vt-py python module. install via pip.

you can use this as an example of how to write a external native module
'''



# class name has to be capitalized module name
class Virustotal(NativeModule):

    speedType = "fast"
    threaded = True


    # include author info for contact and support
    __author__ = "Haoxi Tan"
    __email__  = "haoxi.tan@gmail.com"
    __description__ = "query info about malware hashes on virustotal (need vt-py python3 module). need vt_apikey in config/apikeys.json"


    def setup(self,  sample_path, start_path, output_path):
        self.setup_done = False

        self.sample_path = sample_path
        self.start_path = start_path
        self.output_path = output_path

        apikey = None
        with open('config/apikeys.json', 'r') as fp:
            apiconf = json.load(fp)
        apikey = apiconf.get('vt_apikey', None)

        if apikey == None:
            print("vt api key not found. Did you put it in apikeys.conf in the same directory as run.py?")

        self.client = vt.Client(apikey)
        self.setup_done = True
        print('[virustotal] module setup done!')

    def run(self):
        '''
        setup needs to run before this

        retrieves virustotal info about the files in the sample_path, excluding .viv files generated by capa
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
                if filename.endswith('.viv'):
                    continue
                filepath = os.path.join(root,filename)
                with open(filepath,'rb') as f:
                    buf = f.read()
                    hashes.add(sha1(buf).hexdigest())
        
        count = len(hashes)
        print(f"[virustotal] querying {count} hashes")

        for h in hashes:
            try:
                res = self.client.get_object('/files/' + h)
                # self.client.close()
                print("[virustotal] last_analysis_stats:", str(res.last_analysis_stats)[:30],'...')
                self.output[h] = {}
                self.output[h]['last_analysis_stats'] = res.last_analysis_stats
                self.output[h]['last_analysis_results'] = res.last_analysis_results


            except vt.error.APIError as e:
                if e.message == 'NotFoundError':
                    print('[virustotal] not found on virustotal')
                    pass
                else:
                    print("vt API error:", e)
                continue
                # exit(1)
            except Exception as e:
                # self.client.close()
                print("something went wrong: ", e)
                
        self.client.close()
        print("virustotal done!")

    def get_output(self):
        # print('[virustotal] get_output: ')#, str(self.output)[:10],'...')
        # print(self.output)
        return self.output



        
        

        

    
