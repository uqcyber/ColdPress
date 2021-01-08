#!/usr/bin/bash
#
# Copyright (c) 2020,2021 Oracle and/or its affiliates. All rights reserved.
# 

if [ "$#" -lt 2 ] ; then
    echo "usage: $0 <malware sample dir> <nmae of executable in sample dir> [coldpress args]"
	echo "example:"
	echo "$0 ./samples wannacry.exe"
	echo "or to analyze the whole sample dir:"
	echo "$0 ./samples ."
        exit 1
fi

set -x

OUTDIRPATH="$(pwd)/reports/reports-$(date +%Y%m%d-%H%M%S)"

mkdir -p $OUTDIRPATH

TIMEOUT=30
INDIR=$1
SAMPLEPATH=$2

# shift arguments so users can input args
shift 2
ARGS=$@

docker run -it -v `realpath $INDIR`:/malware/ -v $OUTDIRPATH:/output coldpress python3 run.py -T $TIMEOUT -d /output -s /malware/$(basename $SAMPLEPATH) $ARGS 

echo data is in $OUTDIRPATH



