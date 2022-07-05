#!/usr/bin/env python3
from pathlib import Path
zip_bytes = Path("challenge/dump.zip").read_bytes()

# Extract all the flag bytes
flag = b''
start_index = 0
while start_index != -1:
    # Find
    eocd_index = zip_bytes.find(b"PK\x05\x06", start_index+1)
    lfh_offset = int.from_bytes(zip_bytes[eocd_index+16:eocd_index+16+4], "little")
    flag += zip_bytes[lfh_offset-1:lfh_offset]

    # Next
    start_index = eocd_index

# flag: "CTF{p0s7m0d3rn_z1p}"
print(flag)
