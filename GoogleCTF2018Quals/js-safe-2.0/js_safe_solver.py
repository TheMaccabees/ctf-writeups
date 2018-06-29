import itertools
import string

# this is approximately `h` in the js code
def modified_adler32(string):
    # this function is equivalent to:  struct.unpack('4B', struct.pack('>I', zlib.adler32(string.encode(), 0x821e0a9a)))
    a = 0x0a9a
    b = 0x821e
    for ch in string:
        a = (a + ord(ch)) % 0xfff1
        b = (b + a) % 0xfff1
    return [b >> 8, b & 0xFF, a >> 8, a & 0xFF]

# this is approximately `c` in the js code
def xor_decrypt(encrypted, key):
    return ''.join(chr(c ^ k) for c, k in zip(encrypted, itertools.cycle(key)))

# this is from the html
ALLOWED_FLAG_CHARS = string.ascii_letters + string.digits + '_-@!?'

# this is from within the `eval` in the js
ENCRYPTED_FLAG = [
    0xa2, 0xd7, 0x26, 0x81,
    0xca, 0xb4, 0x63, 0xca,
    0xaf, 0xac, 0x24, 0xb6,
    0xb3, 0xb4, 0x7d, 0xcd,
    0xc8, 0xb4, 0x54, 0x97,
    0xa9, 0xd0, 0x38, 0xcd,
    0xb3, 0xcd, 0x7c, 0xd4,
    0x9c, 0xf7, 0x61, 0xc8,
    0xd0, 0xdd, 0x26, 0x9b,
    0xa8, 0xfe, 0x4a,
]

# this is from within the `eval` in the js
def check_flag(flag):
    assert all(ch in ALLOWED_FLAG_CHARS for ch in flag)
    return flag == xor_decrypt(ENCRYPTED_FLAG, modified_adler32(flag))


### SOLUTION: ###
if __name__ == '__main__':

    HASH_LENGTH = 4

    hash_bytes_possibilities = [
        [
            byte for byte in range(256) if
            all(chr(e ^ byte) in ALLOWED_FLAG_CHARS for e in ENCRYPTED_FLAG[i::HASH_LENGTH])
        ]
        for i in range(HASH_LENGTH)
    ]

    for possible_hash in itertools.product(*hash_bytes_possibilities):
        possible_flag = xor_decrypt(ENCRYPTED_FLAG, possible_hash)
        if check_flag(possible_flag):
            print(possible_flag)