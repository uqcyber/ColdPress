# ColdPress
Extensible Platform for Malware Analysis

ColdPress is an extensible end-to-end pipeline for gathering threat intelligence from malware samples. By integrating state-of-the-art SRE (Software Reverse Engineering) frameworks, Threat Intelligence feeds and Python SRE libraries, ColdPress aims to automate the process of malware analysis and report generation into various formats.

## Building

ColdPress is meant to be used as a Docker container. To build the image:

```
chmod +x build.sh
sudo ./build.sh
```

`build.sh` simply contains commands to run docker build. If you're on Windows, you can run those commands manually.

## Running

To run ColdPress using the `docker_start.sh` script:

`./docker_start.sh ./samples malware.exe`

Where ./samples is where your samples are and `malware.exe` is the file you want to analyze within `./samples`.

To pass arguments, add them to the end. 
E.g. fast mode:
`./docker_start.sh ./samples malware.exe -F`

If you wanted to analyze the entire samples directory:
`./docker_start.sh ./samples .`

Or you could manually start the coldpress container via Docker:
`docker run -it coldpress`

Or spawn a shell inside:
`docker run -it coldpress bash`
