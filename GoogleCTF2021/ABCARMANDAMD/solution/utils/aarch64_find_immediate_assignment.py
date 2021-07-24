#!/usr/bin/env python
# Use this file in order to locate immediate assignment to register in AArch64
# We use ADDS / SUBS pair in order to find proper immediate pairs that both
# are printable.
from keystone import *

def is_valid_encoding(encoding):
    for b in encoding:
        if b < 0x20 or b > 0x7f:
            return False
    return True

ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)

# TODO: change 'wanted_value' to whatever you want
wanted_value = 0x74
for i in range(0 + wanted_value, 4095 - wanted_value):
    inst = f"ADDS W2 , W2 , #{i}; SUBS W2 , W2 , #{i - wanted_value}"
    encoding, count = ks.asm(inst)
    if is_valid_encoding(encoding):
        print(encoding, inst, i)
