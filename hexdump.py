#!/usr/bin/env python3

import sys, string

def dump(file):
	"""
	Documentation...
	"""
    
	try:
		fd = open(file, "rb")
	except:
		print("Error", sys.exc_info([0]))
		sys.exit()
	
	# count how many bytes we have read in
	counter = 0

	bytes = fd.read(16)
	# while still bytes in the file
	while bytes != b"":
		print("%08x" % counter, end="  ")
		counter += 16	

		# print hex values
		i = 1 
		for b in bytes:
			if b:
				if i == 8:
					print("%02x" % b, end="  ")
				else:
					print("%02x" % b, end=" ") # print hex val 2 digits wide
			else:
				print(" ", end="")
			i += 1

		bytesleft = 16 - len(bytes)
		if bytesleft > 0:
			print (3*bytesleft * " ", end="")

		# print ascii values
		print(" |", end="")
		for b in bytes:
			char = ("%c" % b)
			if b and char not in string.whitespace:
				print(char, end="")
			else:
				print(".", end="")
		print("|")
		bytes = fd.read(16)

	counter -= bytesleft
	print("%08x" % counter)

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
