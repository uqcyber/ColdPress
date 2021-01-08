#!/usr/bin/env python3
#
# Copyright (c) 2020,2021 Oracle and/or its affiliates. All rights reserved.
#

from ..modules import NativeModule
import os
import requests
from hashlib import md5
import json
import time

# class name has to be capitalized module name


class Threatminer(NativeModule):

    speedType = "slow"
    threaded = True

    # include author info for contact and support
    __author__ = "Haoxi Tan"
    __email__ = "haoxi.tan@gmail.com"
    __description__ = "query info about malware hashes on threatminer (check https://www.threatminer.org/api.php)"

    def setup(self,  sample_path, start_path, output_path):
        self.setup_done = False

        self.sample_path = sample_path
        self.start_path = start_path
        self.output_path = output_path

        self.setup_done = True
        print('[threatminer] module setup done!')

    def run(self):
        '''
        Please note that the rate limit is set to 10 queries per minute. (60 / 10 = 1 per 6 seconds)

        setup needs to run before this
        threatminer sample query types
        rt      description    example url
        rt=1    Metadata        https://api.threatminer.org/v2/sample.php?q=e6ff1bf0821f00384cdd25efb9b1cc09&rt=1
        rt=2    HTTP Traffic    https://api.threatminer.org/v2/sample.php?q=e6ff1bf0821f00384cdd25efb9b1cc09&rt=2
        rt=3    Hosts (domains and IPs)     https://api.threatminer.org/v2/sample.php?q=e6ff1bf0821f00384cdd25efb9b1cc09&rt=3
        rt=4    Mutants     https://api.threatminer.org/v2/sample.php?q=e6ff1bf0821f00384cdd25efb9b1cc09&rt=4
        rt=5    Registry keys   https://api.threatminer.org/v2/sample.php?q=e6ff1bf0821f00384cdd25efb9b1cc09&rt=5
        rt=6    AV detections   https://api.threatminer.org/v2/sample.php?q=abe4a942cb26cd87a35480751c0e50ae&rt=6
        rt=7    Report tagging  https://api.threatminer.org/v2/sample.php?q=abe4a942cb26cd87a35480751c0e50ae&rt=7

        everything will be queried, with a 1 second delay between each request for rate limiting

        '''

        if not self.setup_done:
            print("setup not done, cannot run.")
            return

        self.output = {}
        files = []
        # use a set to remove dups
        hashes = set()
        for root, directories, filenames in os.walk(self.sample_path):
            # do not recurse; only do level 1
            if root == self.sample_path:
                for filename in filenames:
                    if filename.endswith('.viv'):
                        continue
                    # filepath = os.path.join(self.sample_path,directories,filename)
                    filepath = os.path.join(root, filename)
                    with open(filepath, 'rb') as f:
                        buf = f.read()
                        hashes.add(md5(buf).hexdigest())

        count = len(hashes)
        print(f"[threatminer] querying {count} hashes")

        types = {1: 'metadata', 2: 'http traffic', 3: 'network hosts',
                 4: 'mutant', 5: 'registry keys', 6: 'AV detections', 7: 'linked reports'}

        for h in hashes:
            for t in types:
                url = f"https://api.threatminer.org/v2/sample.php?q={h}&rt={t}"
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.130 Safari/537.36'}
                r = requests.get(url, headers=headers)
                j = json.loads(r.text)
                print('[threatminer] on %s, sleeping 3 seconds..' % h)
                time.sleep(3)
                # print('[threatminer] response:', str(j)[:10])
                if j.get('status_code') == '200':  # response found
                    self.output[h] = {}
                    self.output[h][types[t]] = j.get('results')
                else:
                    print('[threatminer] found nothing, status code:',
                          j.get('status_code'))
                    if t == 1:
                        # if there's no metadata, there's nothing at all - continue to next hash
                        break

        print("threatminer done!")

    def get_output(self):
        # print('[threatminer] get_output: ', str(self.output)[:10],'...')
        return self.output
