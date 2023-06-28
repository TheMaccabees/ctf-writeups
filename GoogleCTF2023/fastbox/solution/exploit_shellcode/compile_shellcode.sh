#!/bin/bash
gcc solution.c syscall.S -nostartfiles -O3 -nostdlib -fPIC -fpie -fcf-protection=none -o solution.elf
objcopy -j.text -Obinary solution.elf solution.shellcode
cat solution.shellcode > shellcode.bin
