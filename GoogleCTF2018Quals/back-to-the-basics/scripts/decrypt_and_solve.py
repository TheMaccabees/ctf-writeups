import functools
import itertools
import re
import struct
import sys

def to_petscii(ascii_bytes):
    # because '+' is used in regexps, we use '#' to denote '+'
    return ascii_bytes.replace(b'=', b'\xb2').replace(b'#', b'\xaa').replace(b'-', b'\xab')

def to_ascii(petscii_bytes):
    return petscii_bytes.replace(b'\xaa', b'+').replace(b'\xab', b'-')

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

def get_challenges(prg):
    challenge_pattern = re.compile(to_petscii(rb'V = (0\.\d+)(?: ([#-]) (0\.\d+))? : G = 0(?:(?!G = ).)+G = (0\.\d+)'), re.DOTALL)
    for V_a, V_op, V_b, G in re.findall(challenge_pattern, prg):
        V = float(V_a)
        V_op = to_ascii(V_op)
        if V_op:
            V += { b'+': 1, b'-': -1 }[V_op] * float(V_b)
        G = float(G)

        yield V, G

def solve_challenge(start, goal):
    additions = [4**(-2-i) for i in range(13)]
    #additions = [0.062500000001818989403545856475830078125,0.0156250000004547473508864641189575195312,0.0039062500001136868377216160297393798828,0.0009765625000284217094304040074348449707,0.0002441406250071054273576010018587112427,0.0000610351562517763568394002504646778107,0.0000152587890629440892098500626161694527,0.0000038146972657360223024625156540423632,0.0000009536743164340055756156289135105908,0.0000002384185791085013939039072283776477,0.0000000596046447771253484759768070944119,0.000000014901161194281337118994201773603,0.0000000037252902985703342797485504434007]

    for addition in additions:
        if start + addition <= goal:
            start += addition
            yield 1
        else:
            yield 0

def chunk(iterable, chunk_len):
    return zip(*[iter(iterable)]*chunk_len)

def bits_to_byte(bits):
    return functools.reduce(lambda byte, bit: (byte << 1) | bit, reversed(bits))

def solve_for_password(prg):
    password_bits = []

    for i, (start, target) in enumerate(get_challenges(prg)):
        solution = list(solve_challenge(start, target))
        print('solved #{:02}: {} -> {} by {}'.format(i + 1, start, target, solution))
        password_bits += solution

    return bytes(bits_to_byte(byte_bits) for byte_bits in chunk(password_bits, 8))

def main(input_filepath):
    # read input prg
    with open(input_filepath, 'rb') as input_file:
        prg = bytearray(input_file.read())

    prg = decrypt_prg(prg)
    password = solve_for_password(prg)
    print('PASSWORD: {}'.format(password))

if __name__ == '__main__':
    main(*sys.argv[1:])
