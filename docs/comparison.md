# Comparison

There are very few projects that aims to achieve a modular, extensive malware analysis pipeline as ColdPress. One very similar platform is [IntelOwl](https://github.com/intelowlproject/IntelOwl), which is a docker based threat intelligence platform that has many analysis modules and threat intel feeds built-in. In contrast to ColdPress, IntelOwl is not a command line tool, but a web-based UI. It is also written in Python. A notable difference is that IntelOwl does not have reverse engineering frameworks that are usually used in manual analysis, such as Ghidra and Radare2 built-in, unlike ColdPress. This results in the lack of reverse engineering specific information in IntelOwl's output, such as disassembly code and flow graphs.

Another platform that can be compared against is [HybridAnalysis](https://www.hybrid-analysis.com/), which employs its commercial Falcon Sandbox to run dynamic analysis to return information, in addition to static analysis. It does not have the same aim of being an extensible solution like ColdPress and IntelOwl, but serves as a typical example of a malware analysis platform with a sandbox (such as [Cuckoo](https://github.com/cuckoosandbox/cuckoo) ).

Table below compares the types of information available via ColdPress, ColdPress in fast mode, IntelOwl and HybridAnalysis. Some types of information are available via multiple extraction methods (they are either returned by multiple modules, or the methods are used in combination to produce the results). Note that information queried via threat intel APIs are subject to availability of the feeds, therefore is not always available. Due to the fact that the development of ColdPress emphasized more on integrating powerful static analysis tools, and IntelOwl focuses more on querying as many threat intel
feeds as possible, the number of threat intel platforms available to query from both tools are different. 

| | |
|:-------------------------:| :-------------------------: |
| ![](./image/comparison.png?raw=true) |        ![](./image/legends.png?raw=true) |  


Table below compares currently integrated threat intelligence platforms in ColdPress and IntelOwl. Note that Cuckoo sandbox is a plugin in OTX, which means data from Cuckoo is included in ColdPress if it is available via OTX.

![](./image/comparison_ti.png?raw=true)