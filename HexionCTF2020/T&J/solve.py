import os
import subprocess
from struct import unpack
from textwrap import wrap
from typing import List
import matplotlib.pyplot as plt

TSHARK = r'C:\Program Files\Wireshark\tshark.exe'
TSHARK_SUCCESS = 0
INPUT_PCAP = os.path.expandvars(r'%USERPROFILE%\Downloads\jerry.pcapng')


def plot(coordinates):
    x_data, y_data = zip(*coordinates)
    plt.plot(x_data, y_data, 'o', markersize=1)
    plt.show()


def moves_to_coordinates(moves, start=0, end=-1000):
    x, y = 0, 0
    for is_clicked, x_diff, y_diff in moves[start:end]:
        x += x_diff
        y -= y_diff
        if is_clicked:
            yield x, y


def hex_to_int8(hex_byte: str):
    return unpack('b', bytes.fromhex(hex_byte))[0]


def interrupts_to_mouse_moves(interrupts: List[str]):
    for interrupt in interrupts:
        fields = wrap(interrupt, 2)
        needed_fields = fields[:3]
        yield map(hex_to_int8, needed_fields)


def extract_field_from_pcap(pcap_path: str, field_name: str):
    cmd = f'"{TSHARK}" -r "{pcap_path}" -T fields -e {field_name}'

    result = subprocess.run(cmd, capture_output=True)
    if result.returncode != TSHARK_SUCCESS:
        raise ChildProcessError(f'Error {result.returncode}: {result.stderr.decode()}')

    return result.stdout.decode()


def main():
    interrupts = extract_field_from_pcap(INPUT_PCAP, 'usb.capdata').splitlines()
    print(f'read {len(interrupts)} usb interrupts from pcap')

    mouse_moves = interrupts_to_mouse_moves(interrupts)
    coordinates = moves_to_coordinates(list(mouse_moves))
    plot(coordinates)


if __name__ == '__main__':
    main()
