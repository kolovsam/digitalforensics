#!/usr/bin/env python3.2

"""
Author: Ryan Connell
Lab3 CS365 Forensics, Spring 2015
"""

"""
Your Name: Sam Kolovson
Who you worked with: Becky Bryan, Jeffrey Lai
"""

import sys
from struct import unpack

class UnpackTester:
    """ A class for learning how to use unpack """

    def run_methods(self):
        """ 
        The methods that will be called that you 
        will fill in below
        """
        self.unpack_bytes()
        self.unpack_shorts()
        self.unpack_longs()
        self.decode_bytes()
        self.join_example()
    
    def unpack_bytes(self):
        """ 
        Unpack all 16 bytes using the unpack command and
        print them out
        """
        #----------------------------------------------------------------
        # Your code goes here

        print (unpack(">16B", self.data))
		
        #----------------------------------------------------------------
    
    def unpack_shorts(self):
        """ 
        Unpack all 8 shorts (which is 16 bytes) using 
        the unpack command and print them out
        """
        #----------------------------------------------------------------
        # Your code goes here

        print (unpack(">8H", self.data))
		
        #----------------------------------------------------------------
    
    def unpack_longs(self):
        """ 
        Unpack all 4 longs (which is 16 bytes) using 
        the unpack command and print them out
        """
        #----------------------------------------------------------------
        # Your code goes here

        print (unpack(">4L", self.data))
		
        #----------------------------------------------------------------
    
    def decode_bytes(self):
        """
        Using bytes.decode(<bytes>) print out all 16
        bytes of the data you read in
        """
        #----------------------------------------------------------------
        # Your code goes here

        print (bytes.decode(self.data))
		
        #----------------------------------------------------------------
    
    def join_example(self):
        """
        Print a smiley face :-) in between each character
        of the character array, chr_array, which contains
        the alphabet, using the join method
        """
        chr_array = []
        for i in range(0,26):
            chr_array.append(chr(i + 97))
        
        #----------------------------------------------------------------
        # Your code goes here

        print (" :-) ".join(chr_array))		
		
        #----------------------------------------------------------------
    
    
    def open_file(self,file_name):
        """ Opens the file passed in as an argument """
        try:
            self.fd = open(file_name,'rb')
        except:
            print("File could not be found, please try again")
            sys.exit()
    
    def read_file(self):
        """ 
        Reads the entire file into the self.data array. It also
        closes the file since we are done with it. 
        """
        self.data = self.fd.read()
        self.fd.close()

def usage():
    """ Prints correct usage and exits """
    print("Usage: python3.2 lab3.py <filename>")

def main():
    """ Simple arg check and runs """
    if len(sys.argv) != 2:
        usage()
    else:
        ut = UnpackTester()
        ut.open_file(sys.argv[1])
        ut.read_file()
        ut.run_methods()

# Standard boilerplate to run main()
if __name__ == '__main__':
    main()