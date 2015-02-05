#!/usr/bin/env python3

"""
Sam Kolovson
CS365: Digital Forensics
Professor Brian Levine
Homework 1: Hexdump
January 2015
"""

import sys

class Strings:
	"""
	Class containing functions to open and read a file in order
	to output all strings of printable characters of length num
	or greater in the file

	Variables:
		_num (int): minimum length of string to print
		_filename (string): the name of the file to read in
		_fd (file): the file being read in

	Functions:
		open_file()
		read_file()
	"""
	def __init__(self, num, filename):
		try:
			self._num = int(num)
		except:
			print("Please input number not letter...")
			print("Error:", sys.exc_info()[0])
		self._filename = filename
		self._fd = None

	def open_file(self):
		""" 
		Opens filename, and calls usage() on error.

		"""
		try:
			self._fd = (open(self._filename, "rb"))
		except IOError as err:
			print("IOError opening file: \n\t%s" % err)
			usage()
		except:
			print("Unexpected error:", sys.exc_info()[0])
			usage()

	def read_file(self):
		"""
		Reads in the file using a string buffer and prints all strings of
		printable characters of length num or greater.

		"""
		self.open_file()

		# read in first 16 bytes
		try:
			data = self._fd.read(16) # we'll do this one line (16 bytes) at a time.
		except:
			print("Unexpected error while reading file:", sys.exc_info()[0])
			sys.exit()

		string = ""		# string buffer
		null_count = 0 	# keep track of null bytes to catch 0x0000

		while data:
			for d in data:
				# if printable char add to string
				if ((d > 31 and d < 127) or d == 10):
					string += "%c" % d
					null_count = 0
				# ignore single 0x00 byte between printable characters
				elif d == 0 and null_count < 1:
					null_count += 1
				# else we hit a non-printable or have 0x0000 so check
				# string greater required length print string
				elif len(string) >= self._num:
					print ("%s" % string)
					string = ""		# reset string
					null_count = 0
				# else string less than required length, print nothing
				else:
					string = ""		# reset string
					null_count = 0

			# read in next 16 bytes
			try:
				data = self._fd.read(16) # we'll do this one line (16 bytes) at a time.
			except:
				print("Unexpected error while reading file:", sys.exc_info()[0])
				sys.exit()


def usage():
	""" Print usage string and exit() """
	print("Usage:\n%s <number> <filename>\n" % sys.argv[0])
	sys.exit()

def main():
	""" Simple arg check and runs """
	if len(sys.argv) == 3:
		strings = Strings(sys.argv[1], sys.argv[2])
		strings.read_file()
	else:
		usage()

# Standard boilerplate to run main()
if __name__ == '__main__':
	main()
	