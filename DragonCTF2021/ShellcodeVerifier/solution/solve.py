import subprocess
import shutil
import argparse
from pathlib import Path
from pwnlib.tubes.process import *
from pwnlib.tubes.remote import *
from pwn import *

COMPILER_FILE = "compiler/compiler.elf"
SOURCE_FILE = "source.bin"

def task_send_file(p: process, file_data: bytes):
    p.sendline(f"{len(file_data)}")
    p.send(file_data)

def main():
    # Arguments
    parser = argparse.ArgumentParser(description='Solve DragonCTF2021 / ShellcodeVerifier')

    parser.add_argument('--remote', dest='remote', action='store_true')
    parser.add_argument('--no-remote', dest='remote', action='store_false')
    parser.set_defaults(remote=False)

    parser.add_argument('--debug', dest='debug', action='store_true')
    parser.add_argument('--no-debug', dest='debug', action='store_false')
    parser.set_defaults(debug=False)

    args = parser.parse_args()

    if not args.remote:
        # Remove sandbox directory (if exists)
        if Path("sandbox").is_dir():
            shutil.rmtree("sandbox")

        # Create process
        p = process("../challenge/main")

        # Debug if needed
        if args.debug:
            gdb.attach(p,
            """b call_shellcode
            """)

    else: # Remote
        # Connect to server
        p = remote("shellcodeverifier.hackable.software", 1337)
        
        # Proof-of-work
        p.recvuntil(b"Please use the following command to solve the Proof of Work: ")
        pow_command = p.recvline()
        pow_result = subprocess.check_output(pow_command.decode('ascii').strip().split(" ") + ["-P"])
        p.sendline(pow_result)

    # Send compiler & source
    task_send_file(p, Path(COMPILER_FILE).read_bytes())
    task_send_file(p, Path(SOURCE_FILE).read_bytes())

    p.interactive()

if __name__ == "__main__":
    main()
