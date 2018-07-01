import itertools
import re
import struct
import sys

def to_petscii(ascii_bytes):
    # because '+' is used in regexps, we use '#' to denote '+'
    return ascii_bytes.replace(b'=', b'\xb2').replace(b'#', b'\xaa').replace(b'-', b'\xab')

def decrypt_prg(prg_data):
    SIZEOF_LOADADDRESS = struct.calcsize('=H')

    # extract load address
    load_address = struct.unpack('=H', prg_data[:SIZEOF_LOADADDRESS])[0]
    print('Load address: 0x{:04x}'.format(load_address))

    # decrypt until there are no more occourences of the decryption loop
    loop_params_re = re.compile(to_petscii(rb'ES = (\d+) : EE = (\d+) : EK = (\d+)'))

    offset = SIZEOF_LOADADDRESS
    for index in itertools.count(1):
        loop_params = re.search(loop_params_re, prg_data[offset:])
        if loop_params is None:
            break
        decrypt_start, decrypt_end, decrypt_with = map(int, loop_params.groups())
        print('decryption #{:02}: ADDing from 0x{:04x} to 0x{:04x} with 0x{:02x}'.format(index, decrypt_start, decrypt_end, decrypt_with))
        for address in range(decrypt_start, decrypt_end + 1):
            file_offset = SIZEOF_LOADADDRESS + address - load_address
            prg_data[file_offset] = (prg_data[file_offset] + decrypt_with) & 0xff
        offset += loop_params.end()

    # delete all weird stuff
    print('deleting weird stuff')
    prg_data = prg_data.replace(b'\0\0\0\0\x8f\0', b'')

    return prg_data

def main(input_filepath, output_filepath):
    # read input prg
    with open(input_filepath, 'rb') as input_file:
        prg = bytearray(input_file.read())

    prg = decrypt_prg(prg)

    with open(output_filepath, 'wb') as output_file:
        output_file.write(prg)

if __name__ == '__main__':
    main(*sys.argv[1:])
