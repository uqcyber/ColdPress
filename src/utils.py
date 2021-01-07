#!/usr/bin/env python3
#
# Copyright (c) 2020,2021 Oracle and/or its affiliates. All rights reserved.
#

import sys
import threading

# terminal colours!
C_HEADER = '\033[95m'
C_BLUE = '\033[94m'
C_CYAN = '\033[0;36m'
C_LIME = '\033[0;82m'
C_GREEN = '\033[32m'
C_YELLOW = '\033[33m'
C_WARNING = '\033[93m'
C_RED = '\033[91m'
C_ENDC = '\033[0m'
C_BOLD = '\033[1m'
C_UNDERLINE = '\033[4m'


# make eprint threadsafe and not mess up terminal outputs
print_lock = threading.Lock()


def eprint(*args, color=None, **kwargs):
    '''
    stderr printing with colors!
    color is an ANSI color sequence
    '''
    global print_lock
    sys.stderr.write("🔒")
    print_lock.acquire()
    if color != None:
        sys.stderr.write(color)
        print(*args, file=sys.stderr, **kwargs)
        # sys.stderr.write(C_ENDC)
    else:
        print(*args, file=sys.stderr, **kwargs)

    sys.stderr.write(C_ENDC)
    sys.stdout.write(C_ENDC)

    print_lock.release()
