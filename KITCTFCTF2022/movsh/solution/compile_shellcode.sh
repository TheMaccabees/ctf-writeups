#!/bin/bash
gcc -nostartfiles -nostdlib solution.S -o solution.bin
objcopy -j.text -Obinary solution.bin solution.shellcode