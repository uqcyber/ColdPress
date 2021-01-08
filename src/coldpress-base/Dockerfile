#
# Copyright (c) 2020,2021 Oracle and/or its affiliates. All rights reserved.
#

# using buster because it has quite a long support, and has packages we need
FROM python:3.9-buster

WORKDIR /usr/src/app

# install build tools and some dependencies
RUN apt update && apt install -y gcc build-essential libfuzzy-dev binwalk

# install ghidra
WORKDIR /opt
ARG GHIDRA_VERSION=9.1.2_PUBLIC_20200212
ARG GHIDRA_SHA256=ebe3fa4e1afd7d97650990b27777bb78bd0427e8e70c1d0ee042aeb52decac61

RUN apt install -y unzip git wget gettext-base patch openjdk-11-jdk-headless && \
    wget -q -O ghidra.zip https://ghidra-sre.org/ghidra_${GHIDRA_VERSION}.zip && \
    echo "${GHIDRA_SHA256} *ghidra.zip" | sha256sum -c && \
    unzip ghidra.zip && \
    rm ghidra.zip && \
    ln -s ghidra* ghidra

# put ghidra's analyzeHeadless in the app dir
RUN ln -s /opt/ghidra/support/analyzeHeadless /usr/src/app/


# install radare2, pre-built binary. works on x86-64
WORKDIR /opt
ARG R2_RELEASE=4.5.1
ARG R2_DEB=radare2-debian-buster_${R2_RELEASE}_amd64.deb

RUN wget https://github.com/radareorg/radare2/releases/download/${R2_RELEASE}/radare2-debian-buster_${R2_RELEASE}_amd64.deb && \
    dpkg -i ${R2_DEB} && \
    rm ${R2_DEB}


#install capa
ARG CAPA_RELEASE=v1.4.1
ARG CAPA_ZIP=capa-${CAPA_RELEASE}-linux.zip
RUN wget https://github.com/fireeye/capa/releases/download/${CAPA_RELEASE}/capa-${CAPA_RELEASE}-linux.zip && \
    unzip ${CAPA_ZIP} && \
    mv capa /usr/bin/ && \
    rm ${CAPA_ZIP}

#download capa-rules
WORKDIR /usr/src/app
RUN git clone --depth 1 https://github.com/fireeye/capa-rules.git 

#download PEiD database and save as 'userdb.txt'
RUN mkdir resource && \
    cd resource && \
    # add a placeholder PEiD databse
    touch userdb.txt 
    #actual userdb can be download from here
    #wget -O userdb.txt https://raw.githubusercontent.com/merces/pev/master/src/userdb.txt

