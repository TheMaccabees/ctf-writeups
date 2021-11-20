#!/bin/bash

# Compile shellcode
cd shellcode
./compile_shellcode.sh
cd ..

# Build ELF payload
nasm -f bin -o payload.elf payload.S

# Print as URL-encoded base64
python3 ./dump_payload_base64_urlencoded.py payload.elf
