.global syscall_func
syscall_func:
    # All arguments are passed via registers.
    # (Not all will be valid, depending on the syscall.)
    mov     %edi, %eax
    mov     %rsi, %rdi
    mov     %rdx, %rsi
    mov     %rcx, %rdx
    mov     %r8,  %r10
    mov     %r9,  %r8
    mov     8(%rsp), %r9

    # Make the system call.
    syscall
    ret