#!/usr/bin/python3

'''
Author: RonXD
'''

import socket
import sys

# The public RSA parameters
e = 65537
n = 0xDA53A899D5573091AF6CC9C9A9FC315F76402C8970BBB1986BFE8E29CED12D0ADF61B21D6C281CCBF2EFED79AA7DD23A2776B03503B1AF354E35BF58C91DB7D7C62F6B92C918C90B68859C77CAE9FDB314F82490A0D6B50C5DC85F5C92A6FDF19716AC8451EFE8BBDF488AE098A7C76ADD2599F2CA642073AFA20D143AF403D1

I = pow((n+1)//2, e, n)

ct = open("flag.txt", "rb").read()
m = int.from_bytes(ct, "big")

def oracle(m):
	con = socket.create_connection(("perfect-secrecy.ctfcompetition.com", 1337))
	con.send(b"\x00")
	con.send(b"\x01")
	con.sendall(m.to_bytes(128, "big"))
	res = con.recv(100, socket.MSG_WAITALL)
	con.close()
	# We just use majority vote...
	return int(res.count(b"\x01") > 50)

def decrypt(m, bits, cur = 0):
	if bits == cur:
		return 0

	bit = oracle(m)
	# This is not necessarily the bit in the original ciphertext!
	print("Got bit {} - {}".format(cur, bit))
	if bit == 0:
		ret = decrypt(m*I%n, bits, cur + 1) * 2
	else:
		ret = decrypt((n-m)*I%n, bits, cur + 1)
		# Only take as many bits as necessary...
		ret = (n - (ret * 2)) & ((1 << bits) - 1)
	return ret

sys.setrecursionlimit(2000)
print(hex(decrypt(m, 1024)))
