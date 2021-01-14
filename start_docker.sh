#!/usr/bin/bash
#
# Copyright (c) 2020,2021 Oracle and/or its affiliates. All rights reserved.
# 

if [ "$#" -lt 1 ] ; then
    echo "usage: $0 <path to malware sample> [coldpress args]"
	echo "example:"
	echo "$0 ./samples/wannacry.exe"
	echo "or to analyze the whole sample dir:"
	echo "$0 ./samples"
        exit 1
fi

set -x

OUTDIRPATH="$(pwd)/reports/reports-$(date +%Y%m%d-%H%M%S)"

mkdir -p $OUTDIRPATH

TIMEOUT=30
INPATH=$1

# shift arguments so users can input args
shift 1
ARGS=$@

if [ -d $INPATH ]; 
then # is a directory
	docker run -it -v `realpath $INPATH`:/malware/ -v $OUTDIRPATH:/output coldpress python3 run.py -T $TIMEOUT -d /output -s /malware $ARGS 
else # is a file
	echo "passing in sample" `basename $INPATH`
	docker run -it -v `realpath $(dirname $INPATH)`:/malware/ -v $OUTDIRPATH:/output coldpress python3 run.py -T $TIMEOUT -d /output -s /malware/`basename $INPATH` $ARGS 
fi

echo data is in $OUTDIRPATH



