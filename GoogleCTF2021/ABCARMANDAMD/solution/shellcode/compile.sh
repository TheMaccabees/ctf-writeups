#!/bin/bash
set -e

# x86-64 shellcode
gcc -nostartfiles -nodefaultlibs x86-64-shellcode.S -o x86-64.elf
objcopy -j.text -Obinary x86-64.elf x86-64.shellcode

# aarch64 print flag shellcode
aarch64-linux-gnu-gcc -nostartfiles -nodefaultlibs aarch64-print-flag.S -o aarch64-flag.elf
objcopy -j.text -Obinary aarch64-flag.elf aarch64-flag.shellcode
python3 aarch64_encoder.py

# aarch64 shellcode
aarch64-linux-gnu-gcc -nostartfiles -nodefaultlibs aarch64-shellcode.S -o aarch64.elf
objcopy -j.text -Obinary aarch64.elf aarch64.shellcode

# Main shellcode
gcc -nostartfiles -nodefaultlibs main.S -o main.elf
objcopy -j.text -Obinary main.elf main.shellcode
