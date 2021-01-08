#!/usr/bin/env python3
#
# Copyright (c) 2020, Oracle and/or its affiliates. All rights reserved.
#

from abc import ABC,abstractmethod 

'''
modules class templates that be loaded via the loader
'''


class Module(ABC):
    '''
    an abstract module class for adding modules 
    '''

    @property
    def speedType(self) -> str:
        '''
        string of "fast" or "slow":
            user defined attribute for mode based operation (fast/slow mode)
        '''
        raise NotImplementedError


    @property
    def threaded(self) -> bool:
        '''
        whether or not this module should run in a thread.
        '''
        ...



class CmdModule(Module):
    '''
    module class to run command line tool - allows for threaded operation
    '''

    def __init__(self):
        ...

    @classmethod
    def get_cmd(self, sample_path, start_path, output_path):
        '''
        returns the command to run, provided sample_path and start_path
        sample_path: the path to the malware sample
        start_path: start path of the pipeline
        '''
        ...


    @classmethod
    def get_output(self, sample_path, start_path, output_path):
        '''
        returns output dictionary
        '''
        ...


class NativeModule(Module):
    '''
    module class to run native python code - allows for threaded operation,
    and consective threaded functions via funcThread
    '''

    def __init__(self):
        '''
        this method will be called by the loader with no extra arguments. will pretty much do nothing
        '''
        ...

    @classmethod
    def setup(self, sample_path, start_path, output_path):
        '''
        initiate important variables and needed configurations
        '''
        ...

    @classmethod
    def run(self):
        '''
        native python code to be ran, with or without a thread depending on
        the threaded variable
        '''
        ...

    @classmethod
    def get_output(self):
        '''
        retrieve output of the module as a dictionary
        '''
        ...



class OutputModule(Module):
    '''
    module that gets ran at the end of the pipeline, utilizing the JSON blob
    to produce different formats of useful outputs (e.g. HTML/TAXII)
    '''

    @classmethod
    def setup(self, start_path):
        '''
        start_path: where run.py, the main script, is
        '''
        ...


    @classmethod
    def get_output(self, data):
        '''
        data: the dictionary data that usually gets written out as JSON
        '''
        ...

    @classmethod
    def get_extension(self):
        '''
        get the file extension (without the dot) of the output file
        '''

        
