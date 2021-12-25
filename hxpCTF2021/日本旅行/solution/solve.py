import subprocess
import shutil
import argparse
from pathlib import Path
from pwnlib.tubes.process import *
from pwnlib.tubes.remote import *
from pwn import *

PAYLOAD_FILE = "payload/payload.elf"

def task_send_file(p: process, file_data: bytes):
    p.sendline(file_data.hex())

def main():
    # Arguments
    parser = argparse.ArgumentParser(description='Solve hxpCTF2021 / 日本旅行')

    parser.add_argument('--remote', dest='remote', action='store_true')
    parser.add_argument('--no-remote', dest='remote', action='store_false')
    parser.set_defaults(remote=False)

    args = parser.parse_args()

    if not args.remote:
        # Create process
        p = remote("localhost", 11111)

    else: # Remote
        # Connect to server
        p = remote("65.108.178.238", 11111)
        
        # Proof-of-work
        # TODO: solve POW using pow-solver.cpp

    # Send compiler & source
    task_send_file(p, Path("payload/payload.elf").read_bytes())
    p.interactive()

if __name__ == "__main__":
    main()
