#!/usr/bin/env python
# This checkes if there are bytes in a given file which are 
# not in the [0x20, 0x7f] range, and prints them.
import sys
shellcode = open(sys.argv[1], "rb").read()
for i, b in enumerate(shellcode):
    if b < 0x20 or b > 0x7f:
        print("index | byte")
        print(hex(i),hex(b))
