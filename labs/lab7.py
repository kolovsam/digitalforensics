#!/usr/vin/env python3

from struct import unpack

def getSigned(bytes):
	"""
	Find the length and pad it to 8 bytes after checking the correct
	bit, unpack and return

	8 bytes is called a long-long and is represented as a 'q' in the
	unpack command: unpack ("<q", ...)[0]

	You can concatenate multiple bytes with "multiplication"
	"\x00*2

	Assume little endian
	"""

	length = len(bytes)

	if length < 8:
		pads = 8 - length

		sig = bytes[length-1]
		#print (sig)

		sig = sig >> 7
		#print (sig)

		# if positive pad with 00
		if sig == 0:
			return unpack("<q", bytes + b'\x00'*pads)[0]
		# if negative pad with FF
		elif sig == 1:
			return unpack("<q", bytes + b'\xFF'*pads)[0]


print (getSigned(b'\xFB\xFD\x9D'))
print (getSigned(b'\xFB\xFD\x1D'))