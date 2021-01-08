#!/usr/bin/env python3
#
# Copyright (c) 2020, Oracle and/or its affiliates. All rights reserved.
#

from __future__ import print_function
import magic
import sys
import os
import pefile
import peutils
import subprocess
import base64
import json
import time
import shlex
import re

import hashlib
import ssdeep 
from libs.pehash import get_pehash
import r2pipe
import mmh3
from libs.machoke import Machoke
# import random

import signal

# multithreaded programming
import threading

import getopt

from utils import *

from modules import loader as module_loader
from modules.modules import *

import tempfile
import shutil
from shutil import copyfile


banner=r'''
            __________
            \++++++++/
                ||
                ||
                ||
                ||
                ||
               /  \
           ___|    |_____
      \ --|              \
       \                 /
        |    ColdPress   |
        |                |
        |   ===========  |
        |  =   *****   = |----\
        |  =    ***    = |    |
        |  =     *     = |    |
        |  =     *     = |    |
        |  =    * *    = |    |
        |  =   ** **   = |    /
        |  = ***   *** = |---/
        |   ===========  |
        |                |
        (\______________/)
       /                 \
      /                   \
     [_____________________]


   Static Malware Analysis Pipeline

'''

print (banner)

# peinfo is mandatory, so no choice
# these are built-in modules originally hardcoded into the pipeline. you can 
# turn them off by just using different command line args (-x or -m)

# this dictionary will expand with external module descriptions
MODULES_ALL = {
            'binwalk':'extract possibly embedded files with binwalk (slow on large files!)',
            'hashes':'generate static and ssdeep hashes',
            'ghidra':'use ghidra to decompile and disassemble binaries',
            'radare2':'radare2 generate import and call graphs',
            'capa':'capa(bilities) of malware, with MITRE ATT&CK mappings',
            'machoke':'CFG based hash (radare2 will be also enabled for this)',
            'regex': 'regular expresssions on strings',
        }

# external / extended modules loaded in will have speed type declared in its own classes
built_in_module_speeds = {
    "binwalk": "slow",
    "hashes": "fast",
    "ghidra": "slow",
    "radare2": "fast",
    "machoke": "slow",
    "regex": "fast"
}

# an array of external module objects
EXTERNAL_MODS = []

GLOBAL_START_PATH = os.getcwd()
DEBUG = False

OUTPUT_DIR = None

# fast mode will mean only fast modules are enabled
FAST_MODE = False

# make a sample directory for grouping input files together, temporarily
tmpdir = tempfile.TemporaryDirectory(prefix="4_sample_tmp_", dir='.').name
os.mkdir(tmpdir)
SAMPLE_DIR = os.path.realpath(tmpdir)

main_output = {}
decomp_output = {}
disass_output = {}

sigint_count = 0

# locks
thread_output_lock = threading.Lock()



def keyboardInterruptHandler(signal, frame):
    global sigint_count
    sigint_count += 1
    eprint("-------KeyboardInterrupt (sig {}) count {}!--------".format(signal, sigint_count), color=C_RED)
    eprint("there are %d threads active:" %threading.activeCount(), color=C_WARNING)
    for t in threading.enumerate():
        eprint(t.getName(), color=C_WARNING)

    filename = "cancelled.json"
    eprint("dumping to cancelled_*.json and exiting....")
    # print(main_output)
    with open(os.path.join(OUTPUT_DIR, "cancelled.json",'w')) as f:
        f.write(json.dumps(main_output))
    with open(os.path.join(OUTPUT_DIR,"cancelled_decomp.json",'w')) as f:
        f.write(json.dumps(decomp_output))
    with open(os.path.join(OUTPUT_DIR,"cancelled_disass.json",'w'))  as f:
        f.write(json.dumps(disass_output))

    exit(1)


class cmdThread(threading.Thread):
    '''
    thread to spawn external tools so that things can be fast
    '''

    def __init__(self, cmd):
        threading.Thread.__init__(self)
        self.cmd = cmd
        self.done = False

    def run(self):
        eprint("started cmdThread %i: %s" %(self.native_id, self.cmd), color=C_UNDERLINE)
        start = time.time()
        # subprocess is thread safe! yes! awesome!
        self.output = subprocess.run(self.cmd.split(),stderr=sys.stderr,stdout=subprocess.PIPE).stdout.decode('utf-8')

        self.done = True

        eprint("[%f seconds] cmdThread %i finished command %s, output %s bytes" %(time.time() - start, self.native_id, self.cmd.split()[0], len(self.output)), color=C_UNDERLINE+C_YELLOW) 

    def get_output(self):
        try:
            return self.output
        except AttributeError as e:
            eprint("cmdThread %i:%s has no output"%(self.native_id, self.cmd), e, color=C_WARNING)

class funcThread(threading.Thread):
    '''
    thread to run a list of [function, [args]] _in order_
    '''

    def __init__(self, funcs):
        threading.Thread.__init__(self)
        self.funcs = funcs

    def run(self):
        start = time.time()
        eprint("started funcThread %i:"%self.native_id, self.funcs, color=C_UNDERLINE+C_CYAN)
        for f in self.funcs:
            func = f[0]
            if (len(f) == 1 or f[1] == None):
                func()
            else:
                func(f[1])

        eprint("[%f] funcThread %i finished:"%(time.time() - start, self.native_id), self.funcs, color=C_UNDERLINE+C_CYAN)

class PEInfo:
    '''
    class to store PE information for analysis
    '''

    def __init__(self, path, modules_enabled=set(MODULES_ALL)):
        '''
        path: path to PE file (NOT a directory)
        '''

        self.path = path

        self.hashes = {}
        self.all_graphs = {}
        self.functions = []
        self.symbols = []

        # ----- start threaded things -----

        self.threads = []
        self.thread_outputs = {}


        if 'capa' in modules_enabled:
            self.threads.append(self.start_capa())
            eprint("started capa on " + self.path, color=C_UNDERLINE+C_YELLOW)
        
        if 'ghidra' in modules_enabled:
            ghidra_thread = self.start_ghidra(os.path.join(OUTPUT_DIR , "ghidra_output"))
            self.ghidra_c_output = ghidra_thread.output_c_file
            self.ghidra_asm_output = ghidra_thread.output_asm_file
            self.threads.append(ghidra_thread)

        
        if 'radare2' in modules_enabled:
            self.r2 = r2pipe.open(self.path)

            self.r2_ft = funcThread([
                                [self.analyze_functions_r2,None],
                                [self.analyze_graphs_r2,None],
                                [self.analyze_misc_r2,None],
                                ])
            self.r2_ft.setName("r2 functions")
            self.threads.append(self.r2_ft)
            self.r2_ft.start()
            eprint("started r2 func thread on " + self.path, color=C_UNDERLINE+C_YELLOW)

        if 'machoke' in modules_enabled:
            machoke_t = funcThread([[self.get_machoke]])
            machoke_t.setName("machoke")
            self.threads.append(machoke_t)
            machoke_t.start()
            eprint("started machoke thread on " + self.path, color=C_UNDERLINE+C_YELLOW)

        
        # threaded external modules

        self.loaded_mods = []

        for mod in EXTERNAL_MODS:
            if isinstance(mod, CmdModule) and mod.threaded:
                modname = mod.__class__.__name__
                mod.setup(SAMPLE_DIR, GLOBAL_START_PATH, OUTPUT_DIR)
                mod_cmd = mod.get_cmd() #self.path, GLOBAL_START_PATH, output_path=OUTPUT_DIR)
                mod_thread = cmdThread(mod_cmd)
                mod_thread.name = modname
                self.threads.append(mod_thread)
                mod_thread.start()
                eprint(f"running threaded cmd mod {modname}", color=C_GREEN)

            if isinstance(mod, NativeModule) and mod.threaded:
                # need to initiate these modules
                modname = mod.__class__.__name__
                mod.setup(SAMPLE_DIR, GLOBAL_START_PATH, OUTPUT_DIR)
                # add the run function of the module into a funcThread, with no args
                mod_thread = funcThread([
                    [mod.run, None]
                    ])
                mod_thread.name = modname
                self.threads.append(mod_thread)
                mod_thread.start()
                eprint(f"running threaded native mod {modname}", color=C_GREEN)




        # r2_start = time.time()
        # eprint("starting r2 stuff for %s"%self.path, color=C_GREEN)
        # self.r2 = r2pipe.open(self.path)
        # self.analyze_functions_r2()
        # self.analyze_graphs_r2()
        # self.analyze_misc_r2()
        # eprint("[{}] r2 stuff done".format(time.time() - r2_start), color=C_LIME)



        # ---------------------------------

        self.pe = pefile.PE(path)
        self.peinfo_json = {}
        self.store_peinfo_json(self.pe, self.peinfo_json)

        if 'hashes' in modules_enabled:
            self.hashes.update(self.generate_hashes())


        # self.analyze_functions_r2()
        # self.r2 pipe should available after analyze_functions_r2() run
        # self.analyze_graphs_r2()

        self.find_regex_strings()

        # self.symbols = json.loads(self.r2.cmd('isj'))

        # detailed string info?
        # self.string_details = json.loads(self.r2.cmd('izj'))




    def join_threads(self, timeout=30):

        threads_done = {}

        for t in self.threads:
            if (t.is_alive()):
                eprint("waiting %fs for thread_%i:%s to terminate" %(timeout, t.native_id, t.getName()), color=C_WARNING)
                # join will block
                t.join(timeout)

            if type(t) == cmdThread:
                
                
                # need to lock this write because of it's threaded
                thread_output_lock.acquire()
                self.thread_outputs[t.getName()] = t.get_output()
                thread_output_lock.release()


                eprint("cmd thread_%i:%s is done, stored output" % (t.native_id, t.getName()), color=C_UNDERLINE)

            if type(t) == funcThread:
                eprint("function thread_%i:%s is done" % (t.native_id, t.getName()), color=C_UNDERLINE)

                # need to lock this write because of it's threaded
                thread_output_lock.acquire()
                threads_done[t.getName()] = t
                thread_output_lock.release()

        print('[join_threads] threads done:', threads_done.keys())
        # reap external threaded module outputs
        for mod in EXTERNAL_MODS:
            if isinstance(mod, NativeModule) and mod.threaded:
                modname = mod.__class__.__name__
                # check if thread is done (added from above)
                if threads_done.get(modname) != None:

                    thread_output_lock.acquire()

                    # t.getName should be the same as modname
                    self.thread_outputs[modname.lower()] = mod.get_output()
                    
                    thread_output_lock.release()
                    
                    eprint(f"ext threaded func {modname} output stored:",str(self.thread_outputs[modname.lower()])[:70], color=C_UNDERLINE+C_GREEN)




    def get_info_output(self):
        '''
        return informational/generic analysis output as a dictionary
        (excluding decompilation and disassembly)
        '''

        output = {}
        try:
            output.update(self.peinfo_json)
            output['hashes'] = self.hashes
            output['graphs'] = self.all_graphs
            output['functions'] = self.functions
            output['symbols'] = self.symbols
            # string details are REALLY REALLY big
            # output['strings'] = self.string_details
            output['regex'] = self.regex
            output['ghidra_debug'] = self.thread_outputs.get('ghidra')

            # rest of the thread_outputs
            eprint('[get_info_output] thread outputs', self.thread_outputs.keys(), color=C_YELLOW+C_UNDERLINE)
            for k in self.thread_outputs:
                if k != 'ghidra' and k != 'capa':
                    print(f"storing thread output {k.lower()} to main output")
                    # store all output keys as lowercase
                    output[k.lower()] = self.thread_outputs[k]

            if self.thread_outputs.get('capa') != None:
                try:
                    # capa uses vivisect. when viv errors out, capa prints the error to STDOUT - so it needs a bit of help if we are to decode the json straight away.
                    capa_json = self.thread_outputs['capa']
                    # find and jump to the start of JSON blob - {"
                    cleaned_capa_json = capa_json[capa_json.find('{"'):]
                    output['capa'] = json.loads(cleaned_capa_json)
                except json.decoder.JSONDecodeError:
                    eprint("Error decoding capa json. Output: {}".format(self.thread_outputs['capa'][:50]), color=C_RED)
            else:
                eprint("%s has no capa output"%self.path , color=C_UNDERLINE+C_WARNING)



        except KeyError as e:
            eprint("KeyError: some output not ready / exist:", e, color=C_UNDERLINE+C_WARNING)
        except AttributeError as e:
            eprint("AttributeError: some output not ready / exist:", e, color=C_UNDERLINE+C_WARNING)

        return output

    def get_decomp_output(self):
        '''
        gets the decompilation output from ghidra, with hashes
        '''

        decomp_output = {'hashes':self.hashes}
        if self.thread_outputs.get('ghidra') != None:
                # store decompilation
                try:
                    with open(self.ghidra_c_output,'r') as f:
                        decomp_output['decompile'] = f.read()
                except Exception as e:
                    eprint(f"get decompile output for {self.path} failed:", e, color=C_WARNING)

        return decomp_output

    def get_disass_output(self):
        '''
        gets the decompilation output from ghidra, with hashes 
        '''

        disass_output = {'hashes':self.hashes}
        if self.thread_outputs.get('ghidra') != None:
                # store decompilation
                try:
                    with open(self.ghidra_asm_output,'r') as f:
                        disass_output['disassembly'] = f.read()
                except Exception as e:
                    eprint(f"get decompile output for {self.path} failed:", e, color=C_WARNING)

        return disass_output


    def start_ghidra(self, output_path="ghidra_output"):
        '''
        start ghidra w/ post analysis scripts
        analyzeHeadless must be added to PATH.
        '''

        # use md5sum as project name 
        buf = open(path,'rb').read()
        md5 = hashlib.md5(buf).hexdigest()
        project_name = md5

        try:
            os.mkdir(os.path.join(OUTPUT_DIR, output_path))
        except FileExistsError:
            pass

        output_c_file = os.path.join(OUTPUT_DIR,output_path,project_name + '.c')
        output_asm_file = os.path.join(OUTPUT_DIR, output_path,project_name + '.asm')

        # ok, f-strings rock!
        cmd = f"./analyzeHeadless {output_path} {project_name} -import {path} -scriptPath {GLOBAL_START_PATH} -postScript libs/decompiler.py {output_c_file} -postScript libs/disassembler.py {output_asm_file}"

        eprint("starting ghidra with command:", cmd, color=C_RED)
        self.ghidra_thread = cmdThread(cmd)
        self.ghidra_thread.setName("ghidra")
        # custom var
        self.ghidra_thread.output_c_file = output_c_file
        self.ghidra_thread.output_asm_file = output_asm_file
        self.ghidra_thread.daemon = True
        self.ghidra_thread.start()
        return self.ghidra_thread

    def start_retdec(self, output_path="retdec_output"):
        buf = open(path,'rb').read()
        md5 = hashlib.md5(buf).hexdigest()
        project_name = md5

        output_c_file = os.path.join(OUTPUT_DIR,output_path,project_name + '.c')
        # output_asm_file = os.path.join(GLOBAL_START_PATH, output_path,project_name + '.asm')

        cmd = f"retdec-decompiler.py --no-memory-limit -o {output_c_file} {path}"
        eprint("starting retdec with command:", cmd, color=C_BLUE)
        self.retdec_t = cmdThread(cmd)
        self.retdec_t.output_c_file = output_c_file
        self.retdec_t.setName("retdec")
        self.retdec_t.daemon = True

        retdec_t.start()

        return self.retdec_t

        # custom var




    def get_hashes(self):
        # try:
        return self.hashes

    def get_functions_json(self):
        if self.functions_json:
            return self.functions_json
        else:
            raise Exception("data requested not available")


    def get_graphs_json(self):
        if self.all_graphs:
            return self.all_graphs
        else:
            raise Exception("data requested not available")

    def get_strings(self):
        '''
        invoke the strings command line util (very fast) and get all the strings 
        '''
        start = time.time()
        strings = subprocess.check_output(['strings', self.path])
        eprint("[%f seconds] strings done on %s: %d bytes" %(time.time() - start, os.path.basename(self.path), len(strings)),  color=C_GREEN)

        return strings


    def find_regex_strings(self):
        '''
        get all strings by running strings tool, then use loose regex (more laxed because malware can have piecewise / broken strings)

        fills self.regex as a dict
        '''

        start = time.time()

        regexes = {'ipv4': r'.*\..*\..*\..*',
                    'dns': r'^((?!-)[A-Za-z0-9-]{1,63}(?<!-)\\.)+[A-Za-z\\.]{2,6}$',
                    'urls': r'[a-z]{2,20}:\/\/.*',
                    'paths': r'.*[.\/\\].*[.\/\\].*'}

        self.regex = {}

        strings = self.get_strings()

        found = 0

        for s in regexes:
            r = re.compile(regexes[s])
            eprint("[%f seconds] starting %s regex" %(time.time() - start, s),  color=C_YELLOW)
            self.regex[s] = []
            for i in strings.split(b'\n'):
                try:
                    i = i.decode('utf-8')
                except:
                    eprint(i, "could not be decoded", color=C_WARNING)
                    continue
                res = r.findall(i)
                self.regex[s].extend(res)
                found += len(res)

        eprint("[%f seconds] regex done on %s, found %d" %(time.time() - start, os.path.basename(self.path), found),  color=C_CYAN)


    def generate_hashes(self):
        '''
        return all hashes as a dict for a file 
        '''
        hashes = {}
        with open(path,'rb') as f:
            buf = f.read()
            hashes['md5'] = hashlib.md5(buf).hexdigest()
            hashes['sha1'] = hashlib.sha1(buf).hexdigest()
            hashes['sha256'] = hashlib.sha256(buf).hexdigest()
            hashes['ssdeep'] = ssdeep.hash(buf)

        start = time.time()
        pe = self.pe

        hashes['pehash'] = get_pehash(pe)

        eprint("[%f seconds] pehash done on %s" %(time.time() - start, os.path.basename(self.path)),  color=C_GREEN)

        # imphash works by hashing IAT
        hashes['imphash'] =  pe.get_imphash()

        return hashes



    def get_sig(self):
        pe = self.pe
        # not used atm
        address = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress
        size = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].Size

        retval.append("\t{} {} {}.der".format(hex(address), size, filename))
        # retval.append("\t%s %s" %(hex(address), size))

        if address == 0:
            return None

        return retval

    def get_import_json(self):
        pe = self.pe
        import_info = {}

        try:
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                entryname = entry.dll.decode()
                import_info[entryname] = {}
                for imp in entry.imports:
                    import_info[entryname]['address'] = imp.address
                    if imp.ordinal == None: 
                        # import_info[entry.dll]['name'] = base64.b64encode(imp.name)
                        import_info[entryname]['name'] = imp.name.decode()
                                
                    else:
                        import_info[entryname]['ordinal'] = imp.ordinal
        except AttributeError as e:
            eprint(e, color=C_WARNING)

        if len(import_info) > 0:
            return import_info 

    def get_export_json(self):
        pe = self.pe 
        export_info = {}
        try:
            if len(pe.DIRECTORY_ENTRY_EXPORT.symbols) > 0:
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    expname = exp.name.decode()
                    export_info[expname] = {}
                    export_info[expname]['address'] = hex(exp.address)
                    export_info[expname]['ordinal'] = exp.ordinal
        except AttributeError as e:
            eprint(e, color=C_WARNING)

        return export_info


    def get_machoke(self):
        start = time.time()
        timeout = False # False or seconds
        # eprint("machoke started...", color=C_YELLOW)
        try:
            m = Machoke(self.path, timeout)
            # if that succeeds, steal r2 pipe from machoke 
            self.r2 = m.rdeux
            self.hashes['machoke'] = m.machoke_line
            eprint("[%f seconds] machoke done on %s" %(time.time() - start, os.path.basename(self.path)),  color=C_GREEN)
        except:
            
            self.hashes['machoke'] = 'timeout'


    def analyze_functions_r2(self):

        # analyze everything first
        funcs = self.r2.cmd('aaa')
        funcs = self.r2.cmd('aflj')

        if funcs != '' and funcs != None:
            # eprint(funcs)
            self.functions = json.loads(funcs)
        else:
            self.functions = []


    def analyze_graphs_r2(self):
        ''' 
        note: r2 pipe must be init by calling analyze_functions_r2 first
        analyze and store flow graph outputs from radare2
        r2 commands are suffixed with output format, in this case j, for json output
        e.g. agi becomes agij
        graphs:
        agi - import graph (which functions import which lib funcs)
        agC - global call graph (which functions call what, including lib funcs)
        agR - global references (what is referencing what, in any section)
        agA - global data references (like above, but only for data sections)

        '''

        start = time.time()
        self.import_graph_json = self.r2.cmd("agij")
        self.global_call_graph_json = self.r2.cmd("agCj")
        self.global_references_json = self.r2.cmd("agRj")
        self.global_data_refs_json = self.r2.cmd("agAj")

        self.all_graphs['imports'] = json.loads(self.import_graph_json)
        self.all_graphs['cfg'] = json.loads(self.global_call_graph_json)
        self.all_graphs['xref'] = json.loads(self.global_references_json)
        self.all_graphs['data_xref'] = json.loads(self.global_data_refs_json)

        eprint("[%f seconds] r2 graphs output on %s: output sizes i:%d C:%d R:%d A:%d" %(time.time() - start, os.path.basename(self.path), len(self.import_graph_json), len(self.global_call_graph_json), len(self.global_references_json), len(self.global_data_refs_json)), color=C_BLUE)


    def analyze_misc_r2(self):
        self.symbols = json.loads(self.r2.cmd('isj'))

    def start_capa(self):
        '''
        runs capa on a sample, but asynchronously using threading
        '''

        self.capa_thread = cmdThread("capa -j -r %s/capa-rules " %GLOBAL_START_PATH + self.path)
        self.capa_thread.setName("capa")
        self.capa_thread.daemon = True
        self.capa_thread.start()
        return self.capa_thread


    def get_peinfo_json(self):
        if self.peinfo_json:
            return self.peinfo_json
        else:
            eprint("peinfo_json is empty!", color=C_WARNING)

    def store_peinfo_json(self, pe, result):
        '''
        result: dictionary object to store results
        '''
        result['entrypoint'] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        result['imagebase'] = hex(pe.OPTIONAL_HEADER.ImageBase) 
        result['linker_version'] = {}
        result['linker_version']['major'] = pe.OPTIONAL_HEADER.MajorLinkerVersion
        result['linker_version']['minor'] = pe.OPTIONAL_HEADER.MinorLinkerVersion
        result['os'] = {}
        result['os']['major'] = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
        result['os']['minor'] = pe.OPTIONAL_HEADER.MinorOperatingSystemVersion 


        if pe.FILE_HEADER.Machine == 0x14c: 
            result['machine'] = 'x86'
        elif pe.FILE_HEADER.Machine == 0x14d:
            result['machine'] = '486'
        elif pe.FILE_HEADER.Machine == 0x14e:
            result['machine'] = 'Pentium'
        elif pe.FILE_HEADER.Machine == 0x0200:
            result['machine'] = 'AMD64 only'
        elif pe.FILE_HEADER.Machine == 0x8664:
            result['machine'] = '64b'
        else:
            result['machine'] = 'Unknown'


        result['compile_timestamp'] = pe.FILE_HEADER.TimeDateStamp

        try:
            result['compile_time_repr'] = "%s UTC" %(time.asctime(time.gmtime(pe.FILE_HEADER.TimeDateStamp))) 
        except ValueError:
            result['compile_time_repr'] = "Invalid Time {}: {}".format(pe.FILE_HEADER.TimeDateStamp, time.asctime(time.gmtime(pe.FILE_HEADER.TimeDateStamp))) 

        try:
            result['header_checksum'] =  pe.IMAGE_OPTIONAL_HEADER.CheckSum
        except AttributeError as e:
            pass

        section_info = {}
        for section in pe.sections:
            name = section.Name.decode()
            # occasionally a nul sneaks in, don't print from the nul to eos
            if "\0" in str(section.Name.decode()):
                nul = name.index("\0")
                name = name[:nul]

            section_info[name] = {}
            section_info[name]['virtual_addr'] = hex(section.VirtualAddress) 
            section_info[name]['virtual_size'] = section.Misc_VirtualSize
            section_info[name]['raw_data_size'] = section.SizeOfRawData
            section_info[name]['entropy'] = section.get_entropy()
        
        result['sections'] = section_info

        result['imports'] = self.get_import_json() 
        result['exports'] = self.get_export_json()

        # digital sig will be extracted via binwalk anyway
        # result['DigitalSignature'] = get_sig(pe)
        try:
            result['optional_header_checksum'] = pe.IMAGE_OPTIONAL_HEADER.CheckSum
        except:
            pass

        # match PEiD signatures
        # sigdata = open("userdb.txt",'r', encoding='ISO-8859-1').read()

        signatures = peutils.SignatureDatabase('resource/userdb.txt')
        matches = signatures.match_all(pe, ep_only = True)

        if matches != None and len(matches) > 0:
            uniq_matches = set()
            for m in matches:
                # print(m)
                uniq_matches.add(m[0])
        
            result['peid'] = list(uniq_matches)





def run_binwalk(path):
    '''
    run binwalk and return a dictionary result
    NOT THREAD SAFE
    '''
    result = {}

    binwalkOutPath = os.path.join(OUTPUT_DIR_BINWALK,'binwalk_files')

    # protect against cmdi
    try:
        os.mkdir(binwalkOutPath, mode=0o755)
    except FileExistsError:
        #pass
        shutil.rmtree(binwalkOutPath)
        eprint(f"[+] Deleted old binwalk files in {binwalkOutPath}")

    # os.chdir(os.path.join(SAMPLE_DIR,"binwalk_files"))

    # print("current dir:", os.getcwd())
    # bw_args = shlex.quote("--dd='.*')
    # print("binwalk target path:", shlex.quote(os.path.realpath(path)))

    binwalk_runcmd = ["binwalk", "--dd=.*", f"--directory={binwalkOutPath}", shlex.quote(os.path.realpath(path))]

    print("binwalk invoke: ", binwalk_runcmd)

    start = time.time()
    if not DEBUG:
        bw_ret = subprocess.call(binwalk_runcmd, stdout=subprocess.DEVNULL)
    else:
        # show output
        eprint("running binwalk...", color=C_BLUE)
        bw_ret = subprocess.call(binwalk_runcmd, stdout=sys.stdout, stderr=sys.stderr)

    eprint ("[%f seconds] binwalk done on %s: returned with " %  (time.time() - start, os.path.basename(path)), bw_ret, color=C_CYAN)

    # now store the result magic of files in json (when recursing, ignore the '0' file which is usually the original)
    try:
        os.chdir(os.path.join(binwalkOutPath, "_" + os.path.basename(path) + ".extracted"))
    except FileNotFoundError as e:
        eprint("binwalk extraction directory not found:", e)

    for f in os.listdir():
        result[f] = {}
        result[f]['magic'] = magic.from_file(f)
        result[f]['size']  = os.path.getsize(f)
        buf = open(f,'rb').read()
        result[f]['sha1'] = hashlib.sha1(buf).hexdigest()


    # go back to the start
    os.chdir(GLOBAL_START_PATH)
    return result


def load_external_modules():
    global MODULES_ALL

    mods = module_loader.load_all()
    for m in mods:
        modname = m.__class__.__name__.lower()
        if MODULES_ALL.get(modname) != None:
            eprint("module name already exists! there's a duplicate!", color=C_FAIL)
            exit(1)
        MODULES_ALL[modname] = m.__description__

    return mods



def usage():
    eprint("%s [options] <file or dir>" % sys.argv[0])
    eprint("options:")
    eprint("-h\thelp")
    eprint("-l\tlist modules")
    eprint("-F\tRun in fast mode, only enable fast modules")
    eprint("-T <timeout>\ttotal timeout in seconds, default 30 per (binwalk) extracted PE file")
    eprint("-t <timeout>\ttimeout per extracted PE file, default 30 (incompatible with -T)")
    eprint("-x <modules>\trun all except these modules, comma separated")
    eprint("-m <modules>\trun only these modules, comma separated (incompatible with -x)")
    eprint("-d <path>\toutput directory to store analysis results and artifacts")
    eprint("-D\tdebug mode (disable ctrl-C handler, extra output...)")


def list_modules():
    for k in MODULES_ALL:
        description = MODULES_ALL[k]
        print(k+':',description)

# ----------------- MAIN ------------------------

if __name__ == "__main__":

    total_timeout = None
    per_pe_timeout = None

    if len(sys.argv) < 2:
        usage()
        exit(1)


    opts, args = getopt.gnu_getopt(sys.argv[1:], 'hlDFT:t:x:m:d:')

    eprint("opts:", opts)
    eprint("args:", args)

    

    # ------------ module loading -------------

    EXTERNAL_MODS = load_external_modules()

    # -----------------------------------------

    modules_enabled = set(MODULES_ALL)
    include_list = None
    exclude_list = None
    # all, include or exclude
    modules_mode = 'all'

    # opts is a dictionary of <opt,arg> tuples e.g. ('-T','60')
    for tup in opts:
        o,a = tup[0], tup[1]
        if o == '-h':
            usage()
            exit(0)
        elif o == '-l':
            list_modules()
            exit(0)

        elif o == '-T':
            total_timeout = float(a)
            eprint(f"total timeout set to {total_timeout}s", color=C_YELLOW)
        elif o == '-t':
            per_pe_timeout = float(a)
            eprint(f"per file timeout set to {per_pe_timeout}s", color=C_YELLOW)

        elif o == '-m':
            modules_mode = 'include'
            include_list = a.split(',')

        elif o == '-x':
            modules_mode = 'exclude'
            exclude_list = a.split(',')

        elif o == '-d':
            OUTPUT_DIR = os.path.realpath(a)

        elif o == '-D':
            DEBUG = True

        elif o == '-F':
            FAST_MODE = True

    #binwalk directory
    OUTPUT_DIR_BINWALK = '/tmp'

    if OUTPUT_DIR == None:
        outdir = "5-output-%d" % time.time()
        OUTPUT_DIR = os.path.realpath(outdir)
        os.mkdir(OUTPUT_DIR)
        eprint("making output dir ", outdir, color=C_GREEN+C_BOLD)

    main_start = time.time()

    if not DEBUG:
        signal.signal(signal.SIGINT, keyboardInterruptHandler)

    pe_analyzed = 0
    samples = 0
    sample_path = path = os.path.realpath(args[0])

    if modules_mode == 'exclude':
        modules_enabled = list(modules_enabled - set(exclude_list))
        for m in EXTERNAL_MODS:
            modname = m.__class__.__name__
            if modname.lower() in exclude_list:
                EXTERNAL_MODS.remove(m)

        EXTERNAL_MODS = list(set(EXTERNAL_MODS) - set(exclude_list))
    elif modules_mode == 'include':
        modules_enabled = include_list


    # now that include and exclude stuff is done, check for fast mode
    # only enable fast modules and nothing else
    if FAST_MODE:
        new_modules_enabled = set()
        for m in modules_enabled:
            # for internal modules
            if built_in_module_speeds.get(m) == 'fast':
                new_modules_enabled.add(m)
        
        # for external modules
        new_external_mods = []
        for m in EXTERNAL_MODS:
            if m.speedType == "fast":
                new_modules_enabled.add(m.__class__.__name__)
                new_external_mods.append(m)
            
        modules_enabled = new_modules_enabled
        EXTERNAL_MODS = new_external_mods

    eprint("modules enabled: ", modules_enabled, color=C_GREEN+C_BOLD)
    eprint("external modules enabled: [", ([str(k.__class__.__name__) for k in EXTERNAL_MODS]) , color=C_GREEN+C_BOLD)

    

    # to store locations of peinfo things in output
    # used for updating info post-analysis
    # <peinfo object, dict> mapping
    peinfo_output_locs = {}
    decomp_output_locs = {}
    disass_output_locs = {}
    input_files = []

    peinfo_all = []

    if os.path.isfile(path):
        input_files.append(path)
        
    else:
        for f in os.listdir(path):
            if os.path.isfile(os.path.join(path, f)):
                input_files.append(os.path.join(path,f))

    for path in input_files:

        basename = os.path.basename(path)

        copyfile(path, os.path.join(SAMPLE_DIR, basename))
        path = os.path.join(SAMPLE_DIR, basename)

        main_output[basename] = {}
        decomp_output[basename] = {}
        disass_output[basename] = {}

        samples += 1 

        if 'binwalk' in modules_enabled:
            main_output[basename]['binwalk'] = run_binwalk(path)
            # copy this to other dictionaries 
            decomp_output[basename]['binwalk'] = main_output[basename]['binwalk'] 
            disass_output[basename]['binwalk'] = main_output[basename]['binwalk'] 

            for f in main_output[basename]['binwalk']:
                if f != '0' and main_output[basename]['binwalk'][f]['magic'].startswith("PE"):
                    filepath = OUTPUT_DIR_BINWALK + "/binwalk_files/_" + basename + ".extracted/" + f

                    peinfo = PEInfo(filepath, modules_enabled)
                    peinfo_all.append(peinfo)
                    # store_peinfo_json(pe, output[basename]['binwalk'][f])
                    peinfo_output_locs[peinfo] = main_output[basename]['binwalk'][f]
                    decomp_output_locs[peinfo] = decomp_output[basename]['binwalk'][f]
                    disass_output_locs[peinfo] = disass_output[basename]['binwalk'][f]
                    # output[basename]['binwalk'][f].update(peinfo.get_all_output())
                    pe_analyzed += 1


        main_output[basename]['filetype'] = magic.from_file(path)
        decomp_output[basename]['filetype'] = main_output[basename]['filetype']
        disass_output[basename]['filetype'] = main_output[basename]['filetype']

        if not main_output[basename]['filetype'].startswith("PE"):
            eprint("file is not a PE file. exiting.")
            #exit(1) 
            continue


        peinfo = PEInfo(path, modules_enabled)
        peinfo_all.append(peinfo)
        peinfo_output_locs[peinfo] = main_output[basename]
        decomp_output_locs[peinfo] = decomp_output[basename]
        disass_output_locs[peinfo] = disass_output[basename]
        # output[basename].update(peinfo.get_all_output())
        pe_analyzed += 1

    # reap / join all the threads in peinfo_all

    eprint("\n-------------------------------\n[elasped %f] joining all threads...\n-------------------------------\n" % (time.time() - main_start), color=C_YELLOW)

    # start joining all threads

    # default timeouts 
    default_timeout_per_file = 60
    timeout_s = default_timeout_per_file  * pe_analyzed

    if total_timeout != None:
        timeout_s = total_timeout

    elif per_pe_timeout != None:
        timeout_s = per_pe_timeout * pe_analyzed


    for p in peinfo_all:
        ft = funcThread([[p.join_threads, timeout_s]])
        ft.start()
        # p.join_threads()

    # eprint("sleeping {} seconds".format(timeout), color=C_UNDERLINE+C_YELLOW)

    check_thread_count = 0
    while threading.activeCount() > 1:
        names = []
        onlyPoolLeft = True
        for t in threading.enumerate():
            names.append(t.getName())
            if t.getName() != 'MainThread' and not (t.getName().startswith('ThreadPoolExecutor')):
                onlyPoolLeft = False

        if onlyPoolLeft:
            break

        eprint("\r[{}/{}s] {} threads left".format(check_thread_count, timeout_s, threading.activeCount()), ','.join(names),color=C_BLUE)
        sleep_secs = 3
        time.sleep(sleep_secs)
        check_thread_count += sleep_secs
        if check_thread_count > timeout_s:
            eprint("thread joining timeout, stopping...", color=C_WARNING)
            break


    for p in peinfo_all:
        output_loc = peinfo_output_locs[p]
        decomp_loc = decomp_output_locs[p]
        disass_loc = disass_output_locs[p]
        
        p.join_threads(timeout=0)
        eprint('before output_loc update: ', len(str(output_loc)), 'chars', color=C_LIME+C_UNDERLINE)
        output_loc.update(p.get_info_output())
        eprint('after output_loc update: ', len(str(output_loc)), 'chars', color=C_LIME+C_UNDERLINE)

        if 'ghidra' in modules_enabled:
            decomp_loc.update(p.get_decomp_output())
            disass_loc.update(p.get_disass_output())
        # close r2 pipe
        # p.r2.quit()


    # print(json.dumps(output))

    # store decompile and disassembly separately, and delete it from main output

    # decomp_out = {'hashes':output['hashes'], 'decompile':main_.pop('decompile', None)}
    # disass_out = {'hashes':output['hashes'], 'disassembly':output.pop('disassembly', None)}

    # write to output file 
    write_start = time.time()
    eprint("writing to output file...", color=C_YELLOW)
    outfile = os.path.join(OUTPUT_DIR, 'info.json')
    outbytes = 0
    with open(outfile,'w') as f:
        outbytes += f.write(json.dumps(main_output))

    if 'ghidra' in modules_enabled:
        decomp_outfile = os.path.join(OUTPUT_DIR,'decomp.json')
        with open(decomp_outfile,'w') as f:
            outbytes += f.write(json.dumps(decomp_output))

        disass_outfile = os.path.join(OUTPUT_DIR,'disass.json')
        with open(disass_outfile,'w') as f:
            outbytes += f.write(json.dumps(disass_output))

    eprint(f"[✅ {time.time() - write_start}] done writing to all json files", color=C_LIME+C_BOLD)

    # now write to output modules!
    for mod in EXTERNAL_MODS:
        if isinstance(mod, OutputModule):
            modname = mod.__class__.__name__
            mod.setup(GLOBAL_START_PATH)
            modOutput = mod.get_output(main_output)
            with open(os.path.join(OUTPUT_DIR, modname + '.' + mod.get_extension()), 'wb') as f:
                f.write(modOutput.encode('utf-8'))
            eprint(f"running output module {modname}", color=C_CYAN)

    time_elasped = time.time() - main_start
    pe_s = time_elasped / pe_analyzed
    sample_s = time_elasped / len(input_files)

    eprint(f"[+] done. analyzed %d samples, %d PE files, %d bytes of output written to {OUTPUT_DIR}" % (samples, pe_analyzed,outbytes), color=C_GREEN)
    eprint("[+] time elapsed: %f seconds, %fs / sample, %fs / PE file" % (time_elasped, sample_s, pe_s), color=C_GREEN)

    #delete binwalk files:
    '''
    binwalkOutPath = os.path.join(OUTPUT_DIR_BINWALK,'binwalk_files')
    if os.path.exists(binwalkOutPath):
        import shutil
        #shutil.rmtree(binwalkOutPath)
        eprint(f"[+] Deleted binwalk files in {binwalkOutPath}")
    '''

    os._exit(0)
