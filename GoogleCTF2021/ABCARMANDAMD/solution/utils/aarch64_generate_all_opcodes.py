#!/usr/bin/env python
# To generate all possible AArch64 instructions, run:
#   $ python3 aarch64_generate_all_opcodes.py 
#   $ ./dump_aarch64.sh all_opcodes.bin | grep -v undefined > all_opcodes.txt
# Now you can grep 'all_opcodes.txt' to find interesting instructions ;)
import random

f = open("all_opcodes.bin", "wb")
for b1 in range(0x20, 0x80):
    for b2 in range(0x20, 0x80):
        for b3 in range(0x20, 0x80):
            for b4 in range(0x20, 0x80):
                f.write(bytes([b1, b2, b3, b4]))
f.close()
