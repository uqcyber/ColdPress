# Overview

The goal of this project is to automate the malware reverse engineering work flow. This includes building a pipeline that automatically extracts malicious features and indicators of compromise using different open source libraries, tools and threat intelligence (TI) feeds.
  
    

# ColdPress Architecture

![ColdPress architecture](./docs/image/coldpress_architecture.png?raw=true)
  
## Key Components

1. ### Recursive file extraction
[Binwalk](https://github.com/ReFirmLabs/binwalk) is used to feed extracted files back into the pipeline manager for further analysis, as many samples contain other files within itself. Recursive analysis will be performed with limited depth, as false positives do exist in Binwalk's extraction process.

2. ### Extensible modules
The system exposes an external module loader to allow users to define their own modules in Python. This allows the pipeline to be easily extensible without modifying the core source code. This is much inspired by the successful architectures of open source security testing frameworks, [BeEF](https://github.com/beefproject/beef) and [Metasploit](https://github.com/rapid7/metasploit-framework). The added modules can be any type (native python code, command line tool, or threat intel API).

**_On demand module toggling:_** All loaded modules can be toggled when ColdPress is run on the command line, to optimize usability of the pipeline. Both an include mode and exclude mode are built into the system to allow users to only run or not run specified modules.

3. ### Multi-threading
The amount of modules implemented into CP means that the pipeline would be very slow if they run sequentially. Only a few modules need to be run sequentially before others (such as [Binwalk](https://github.com/ReFirmLabs/binwalk), to extract other embedded files from a given sample before feeding them back into other modules). Others can run in parallel, to utilize the multi-core nature
of modern CPUs. 

Some malware samples would take a lot longer to run in some modules. For example, a sample with many functions and control 
ows would cause a path-explosion in tools such as [Ghidra](https://github.com/NationalSecurityAgency/ghidra) and [capa](https://github.com/fireeye/capa), clogging up the execution time. This is solved in ColdPress via user-defined timeouts, which can be specified per sample or in total. If at any point the user forces ColdPress to exit an interrupt signal (Ctrl-C), all the data currently available will be written to JSON files and ColdPress would exit

4. ### Fast mode
The system is designed to handle malware samples with batch processing. This allows a large amount of samples to be analyzed at once, increasing work ow efficiency. However, the number of malware samples that can analyzed in parallel depends on the amount of CPU power and memory available on the computer, as all modules in all samples execute in parallel by default. This is why ColdPress has a built-in fast mode. Each module has an attribute that specifies if it is a _fast_ or _slow_ module. When fast mode is toggled, only _fast_ modules would be executed. This speed attribute is user-defined, which means when extending the pipeline, users need to measure the execution time of their new module
and decide whether or not it can be run in fast mode.
  
    
# Integrated Modules

All libraries and tools integrated into ColdPress are open-source. There are many types of modules, including Python libraries, Software Reverse Engineering (**SRE**) frameworks, Threat Intelligence (**TI**) APIs, Command Line Interface (**CLI**) tools, and output formatting modules.

Table below shows the modules currently integrated in ColdPress. Modules marked with _*_ are external modules - meaning that they are written as user-defined modules that does not modify the ColdPress code base, and loaded into the pipeline at run time. These also serve as templates to allow technical users to easily add their own modules. Modules marked with _+_ are _fast_ modules. Whether a module is _fast_ or _slow_ is user-defined for optimal control of the pipeline.

| Python Libs | SRE Frameworks | TI APIs | CLI tools | Output |
| --- | --- | --- | --- | --- |
| [hashlib](https://github.com/python/cpython/blob/master/Lib/hashlib.py)+ | [Ghidra](https://github.com/NationalSecurityAgency/ghidra) | [VirusTotal](https://www.virustotal.com/gui/home/upload)*+ | [Binwalk](https://github.com/ReFirmLabs/binwalk) | JSON+ |
| [ssdeep](https://github.com/ssdeep-project/ssdeep)+ | [Radare2+](https://github.com/radareorg/radare2) | [OTX](https://github.com/AlienVault-OTX/OTX-Python-SDK)*+ | [capa](https://github.com/fireeye/capa) | |
| [pefile](https://github.com/erocarrera/pefile)+ | | [ThreatMiner](https://www.threatminer.org/)* | | |

  
    
# Usage

ColdPress is written in Python and built as a Docker container. To build the Docker image: run `./build.sh`. To run ColdPress, one could spawn a shell inside the Docker container `docker run -it coldpress bash` and then run the main script `run.py` inside the container. For better usability, a shell script docker_start.sh is available for quick spawning of the Docker container. It takes a directory as the first argument to mount into the Docker container. One can use the sample benign binary provided (`samples/minihash.exe`) to test ColdPress.

   
1. To batch-analyze an entire folder of samples: 
```./docker_start.sh /sample/path/to/mount <args>``` (e.g., `./docker_start.sh samples/ .`)
  
2. To analyze only one sample inside a directory, assuming that the file “filename” exists within that directory: 
```./docker_start.sh /sample/path/to/mount filename <args>``` (e.g., `./docker_start.sh samples/ minhash.exe`)

3. Update Virustotal and OTX API keys in the config file located `config/apikeys.json`
  
There are many command-line switches, such as `-T <totaltimeout>`, `-x <m1,m2,..>` to exclude modules by name, `-m <m1,m2,..>` to include modules by name, and so on. They can be added at the end of the arguments. For example, to run in fast mode: ```./docker_start.sh /sample/path/to/mount filename -F``` (e.g., `./docker_start.sh samples/ minhash.exe -F`)

Command-line switches available in ColdPress:
```
options:
	-h    help
	-l    list modules
	-F    Run in fast mode, only enable fast modules
	-D    debug mode (disable ctrl-C handler, extra output...)
	-T <timeout>  total timeout in seconds, default 30 per (binwalk) extracted PE file
	-t <timeout>  timeout per extracted PE file, default 30 (incompatible with -T)
	-x <modules>  run all except these modules, comma separated
	-m <modules>  run only these modules, comma separated (incompatible with -x)
	-d <path>     output directory to store analysis results and artifacts
```

For more details on the usage, please check this [demo video in Youtube](https://youtu.be/2sHmEU6NAGg)

# Comparison

A detailed comparison with existing tools can be found [here](./docs/comparison.md) 

# Limitations

These are the current limitations of ColdPress:
1. Performs no dynamic analysis (some dynamic analysis results are returned via TI if available)
2. Only PE files supported
3. Does not perform malware auto-unpacking

# Note:

Depending of the network speed, it'll take a while to build the ColdPress base image, located under `src/coldpress-base`, so please be patient. 

# License
Copyright (c)  2020, Oracle and/or its affiliates.  All rights reserved.
This software is licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl
See [LICENSE](LICENSE) for more details.