#
# Copyright (c) 2020,2021 Oracle and/or its affiliates. All rights reserved.
#

# build it from a base container with all the prerequisites so you can rebuild the container faster
FROM coldpress-base

WORKDIR /usr/src/app

# copy all files over
COPY . .


# find and install *all* requirements.txt files  
RUN find . -type f -name requirements.txt | xargs cat | pip3 install -r /dev/stdin


WORKDIR /usr/src/app

CMD [ "python", "tests/test.py" ]
