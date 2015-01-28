#!/usr/bin/env python3

import sys, string

def dump(file):
	"""
	Args:
		file (file): file to be read in

	Attributes:
		fd (file): the file being read in
		counter (int): how many bytes have been read in so far
		bytes (array): 
		i (int): counts how many hex values are printed for proper formatting
		bytesleft (int): how many empty bytes in the last bytes array for proper formmatting
		char (char): the printable character as read from the byte	

	Prints:
		hexdump of the inputted file
	"""
    
	try:
		fd = open(file, "rb")
	except:
		print("Error", sys.exc_info([0]))
		sys.exit()
	
	counter = 0		# count how many bytes we have read in

	bytes = fd.read(16)		# read in first 16 bytes of the file to an array

	# while still bytes in the file
	while bytes != b"":
		print("%08x" % counter, end="  ")	# print the counter as a 8 digit hex value
		counter += 16	# add 16 bytes to the counter	

		"""
		Print hex values

		Example:
			29 3a 0a 09 70 72 69 6e  74 28 22 45 72 72 6f 72
		"""
		i = 1	# count bytes so know when to put 2 spaces in the middle 
		for b in bytes:
			if b:
				if i == 8:
					print("%02x" % b, end="  ")
				else:
					print("%02x" % b, end=" ") # print hex val 2 digits wide
			else:
				print(" ", end="")
			i += 1

		bytesleft = 16 - len(bytes)		# calculate empty space for last line
		if bytesleft:
			print (3*bytesleft * " ", end="")

		"""
		Print ascii values

		Example:
			|1])..else:...usa|
		"""
		print(" |", end="")
		for b in bytes:
			char = ("%c" % b)	# print byte as ascii character
			if b and char not in string.whitespace: # non-printable characters
				print(char, end="")
			else:
				print(".", end="")
		print("|")
		bytes = fd.read(16)

	counter -= bytesleft	# accurately computer number of bytes read 
	print("%08x" % counter) # print final byte count on its own line

def usage():
	print("Error:/n")
	print("USAGE: hexdump.py filename")

def main():
	if len(sys.argv) == 2:
		dump(sys.argv[1])
	else:
		usage()

if __name__ == "__main__":
	main()
