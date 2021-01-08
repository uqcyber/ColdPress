#!/usr/bin/bash
#
# Copyright (c) 2020,2021 Oracle and/or its affiliates. All rights reserved.
#

#build the base image
cd src/coldpress-base
time docker build -t coldpress-base .

cd ..
time docker build -t coldpress .
