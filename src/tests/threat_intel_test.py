#!/usr/bin/env python3
#
# Copyright (c) 2020,2021 Oracle and/or its affiliates. All rights reserved.
#

import unittest
import tempfile
import os
import json
import subprocess
import inspect
import sys
import getopt
from pathlib import Path
sys.path.append(str(Path(os.path.dirname(__file__)).parent))
from utils import *


class ThreatIntelTest(unittest.TestCase):
    '''
    Test threat intel extraction

    Please modify the setup class's cmd variable to include new modules names to test when you are testing
    '''

    @classmethod
    def setUpClass(self):
        # dir for testing output

        # this only extracts the name
        tmpdir = tempfile.TemporaryDirectory(prefix="9_test_", dir='.').name
        os.mkdir(tmpdir)
        testdir = self.testdir = os.path.realpath(tmpdir)

        self.binwalk_path = os.path.join("/tmp", "binwalk_files")
        self.ghidra_path = os.path.join(self.testdir, "ghidra_output")

        os.mkdir(self.binwalk_path)
        os.mkdir(self.ghidra_path)

        self.samplename = samplename = "minihash.exe"

        # load expected case
        expected_TI_info_path = os.path.join(
            "tests", "test_expected", "minihash", "info.json")
        with open(expected_TI_info_path, 'rb') as f:
            self.ti_expected = json.loads(f.read())[samplename]
            print("loaded expected TI info: ", str(self.ti_expected)[:50])

        # now run the main program with arguments
        timeout = 300  # 5 minutes is plenty

        samplepath = self.samplepath = os.path.join(
            "tests", "testbin/" + self.samplename)

        # test only the threat intel classes. Please modify this when adding new modules
        MODULES_TO_TEST = ','.join(['virustotal', 'otx', 'threatminer'])
        cmd = f"python3 run.py -m {MODULES_TO_TEST} -d {self.testdir} -T {timeout} -D -s {samplepath}"
        subprocess.run(cmd.split(), stderr=sys.stderr, stdout=sys.stdout)

        # get results
        f = open(os.path.join(testdir, "info.json"), 'r')
        self.ti_real = json.loads(f.read())['minihash.exe']
        f.close()

    def test_vt(self):
        '''
        test virustotal integration. (needs API key) Note that results from virustotal / other online
        platforms can change. This module will ensure that the new data returned is always 
        bigger or equal sized than the expected result.
        '''

        expected = set(self.ti_expected.get('virustotal'))
        real = set(self.ti_real.get('virustotal'))
        print(
            f"expected: {len(str(expected))}bytes real: {len(str(real))}bytes ")
        self.assertGreaterEqual(real, expected)

    def test_threatminer(self):
        '''
        test threatminer integration. note that threatminer has a strict API rate limit
        of 10 requests/min, so some information might not be complete if ran multiple times
        in a short time frame.
        '''

        expected = set(self.ti_expected.get('threatminer'))
        real = set(self.ti_real.get('threatminer'))
        print(
            f"expected: {len(str(expected))}bytes real: {len(str(real))}bytes ")
        self.assertGreaterEqual(real, expected)

    def test_otx(self):
        '''
        test OTX integration. OTX API key required for the data to be returned
        '''

        expected = set(self.ti_expected.get('otx'))
        real = set(self.ti_real.get('otx'))
        print(
            f"expected: {len(str(expected))}bytes real: {len(str(real))}bytes ")
        self.assertGreaterEqual(real, expected)


def main():

    unittest.main()


if __name__ == "__main__":
    main()
