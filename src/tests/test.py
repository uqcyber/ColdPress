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
import time
import sys
import getopt
from pathlib import Path
sys.path.append(str(Path(os.path.dirname(__file__)).parent))
from utils import *


class PipelineTest(unittest.TestCase):
    '''
    extraction "module" based testing

    '''

    @classmethod
    def setUpClass(self):
        # dir for testing output

        # this only extracts the name
        tmpdir = tempfile.TemporaryDirectory(prefix="9_test_", dir='.').name
        os.mkdir(tmpdir)
        testdir = self.testdir = os.path.realpath(tmpdir)

        self.binwalk_path = os.path.join('/tmp', "binwalk_files")
        self.ghidra_path = os.path.join(self.testdir, "ghidra_output")
        # os.mkdir(testdir)

        os.mkdir(self.binwalk_path)
        os.mkdir(self.ghidra_path)

        # load expected case
        expected_info_path = os.path.join(
            "tests", "test_expected", "minihash", "info.json")
        expected_decomp_path = os.path.join(
            "tests", "test_expected", "minihash", "decomp.json")
        expected_disass_path = os.path.join(
            "tests", "test_expected", "minihash", "disass.json")
        # json file might be really big
        with open(expected_info_path, 'rb') as f:
            self.info_expected = json.loads(f.read())
        with open(expected_decomp_path, 'rb') as f:
            self.decomp_expected = json.loads(f.read())
        with open(expected_disass_path, 'rb') as f:
            self.disass_expected = json.loads(f.read())

        print(
            f"successfully loaded expected info file, {len(self.info_expected)} keys")
        print(f"test output dir is {self.testdir}")

        # now run the main program with arguments
        timeout = 30
        self.samplename = "minihash.exe"
        samplepath = self.samplepath = os.path.join(
            "tests", "testbin/" + self.samplename)

        # go back out to the main directory
        cmd = f"python3 run.py -d {self.testdir} -T {timeout} -D -s {samplepath}"
        subprocess.run(cmd.split(), stderr=sys.stderr, stdout=sys.stdout)

        # after running, get the files
        f = open(os.path.join(testdir, "info.json"), 'r')
        self.info_real = json.loads(f.read())
        f.close()
        f = open(os.path.join(testdir, "decomp.json"), 'r')
        self.decomp_real = json.loads(f.read())
        f.close()
        f = open(os.path.join(testdir, "disass.json"), 'r')
        self.disass_real = json.loads(f.read())
        f.close()

    def test_binwalk(self):
        '''
        invoke binwalk and check the number + sizes of extracted files
        '''
        eprint("testing binwalk..", color=C_YELLOW)
        binwalk_files = os.listdir(os.path.join(
            self.binwalk_path,
            "_" + os.path.basename(self.samplepath) + ".extracted"))

        expected = list(self.info_expected[self.samplename]['binwalk'])
        eprint("actual binwalk files:", binwalk_files, color=C_CYAN)
        eprint("expected binwalk files:", expected, color=C_CYAN)

        self.assertEqual(set(binwalk_files), set(expected))
        # this prints the function's own name
        eprint(f"{inspect.stack()[0][3]} passed!", color=C_GREEN+C_BOLD)

    def test_peinfo(self): 
        '''
        test peinfo returned from analysis
        '''
        expected = []
        real = []
        keys = ['filetype', 'entrypoint', 'imagebase', 'linker_version', 'os', 'machine',
                'compile_timestamp', 'compile_time_repr', 'sections', 'imports', 'peid']

        for k in keys:
            expected.append(self.info_expected[self.samplename].get(k))
            real.append(self.info_real[self.samplename].get(k))

        self.assertEqual(expected, real)
        eprint(f"{inspect.stack()[0][3]} test passed!", color=C_GREEN+C_BOLD)

    def test_hashes(self):
        expected = set(self.info_expected[self.samplename]['hashes'])
        real = set(self.info_real[self.samplename]['hashes'])

        self.assertEqual(expected, real)
        eprint(f"{inspect.stack()[0][3]} passed!", color=C_GREEN+C_BOLD)

    def test_capa(self):
        expected = set(self.info_expected[self.samplename]['capa'])
        real = set(self.info_real[self.samplename]['capa'])

        self.assertEqual(expected, real)
        eprint(f"{inspect.stack()[0][3]} passed!", color=C_GREEN+C_BOLD)

    def test_graphs(self):
        '''
        test the four graphs:

        import graph (which functions import which lib funcs)
        global call graph (which functions call what, including lib funcs)
        global references (what is referencing what, in any section)
        global data references (like above, but only for data sections)

        '''

        expected = []
        real = []
        graphs = ['imports', 'cfg', 'xref', 'data_xref']

        for k in graphs:
            expected.append(self.info_expected[self.samplename]['graphs'][k])
            real.append(self.info_real[self.samplename]['graphs'][k])

        self.assertEqual(expected, real)
        eprint(f"{inspect.stack()[0][3]} test passed!", color=C_GREEN+C_BOLD)

    def test_regex(self):
        '''
        regex extraction strings *can* defer as long as the original expected strings are _NOT LOST_.
        '''

        expected = self.info_expected[self.samplename]['regex']
        real = self.info_real[self.samplename]['regex']

        # make sure strings are not lost
        for category in expected:
            for s in expected[category]:
                self.assertTrue(s in real[category])

        if expected != real:
            eprint(
                f"[{inspect.stack()[0][3]}] regex strings are not lost, but differ.", color=C_WARNING)

        eprint(f"{inspect.stack()[0][3]} passed!", color=C_GREEN+C_BOLD)

    def test_ghidra(self):
        '''
        testing ghidra decompilation and disassembly output - not the debug as it can change.
        '''
        real_disass = self.disass_real[self.samplename]['disassembly']
        real_decomp = self.decomp_real[self.samplename]['decompile']

        self.assertEqual(
            real_disass, self.disass_expected[self.samplename]['disassembly'])
        self.assertEqual(
            real_decomp, self.decomp_expected[self.samplename]['decompile'])

        eprint(f"{inspect.stack()[0][3]} passed!", color=C_GREEN+C_BOLD)


def main():

    unittest.main()


if __name__ == "__main__":
    main()
