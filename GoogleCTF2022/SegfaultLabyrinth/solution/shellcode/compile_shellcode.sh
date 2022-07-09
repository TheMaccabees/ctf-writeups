#!/bin/bash

# Compile Basic solution
gcc basic/solution.c syscall.S -nostartfiles -O3 -nostdlib -fPIC -fpie -fcf-protection=none -o solution.elf

# Compile "Hard mode" solution
# gcc hard/solution.c syscall.S -nostartfiles -O3 -nostdlib -fPIC -fpie -fcf-protection=none -o solution.elf

# Compile "Impossible mode" solution
# gcc impossible/solution.S -nostartfiles -O3 -nostdlib -fPIC -fpie -fcf-protection=none -o solution.elf

# Extract the shellcode
objcopy -j.text -Obinary solution.elf solution.shellcode

# Add a "lea rsp,[rip+0xcf0]" to allocate a stack (at the end of the current page)
# This is because rsp is zeroed-out when calling our shellcode, but our page is RWX so there
# is no problem for using it as a stack
echo -en "\x48\x8D\x25\xF0\x0C\x00\x00" > shellcode.bin
cat solution.shellcode >> shellcode.bin
