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

class MysteryWord:
    """ A class for finding the "mystery word" in a file """

    def get_info(self):
        """
        Reads in a long followed by a byte which correspond to the offset 
        of the hidden word (from the beginning of the file) and the length
        of the word, respectively.
            Ex. If the first 8 bytes are: 00 01 02 03 04 05 06 07
            self.word_offset should be 00 01 02 03
            self.word_length should be 04
        """
        #----------------------------------------------------------------
        # Your code goes here

        (self.word_offset,) = unpack(">L", self.fd.read(4))
        (self.word_length,) = unpack(">B", self.fd.read(1))
		
        #----------------------------------------------------------------
        

    def find_word(self):
        """
        Goes to self.word_offset (remember that bytes you already read are
        counted as part of that offset) and prints out the decoded word
        HINT: Use bytes.decode(<bytes>) 
        """
        #----------------------------------------------------------------
        # Your code goes here

        self.fd.read(self.word_offset-5)
        print (bytes.decode(self.fd.read(self.word_length)))
		
        #----------------------------------------------------------------
        
    
    def open_file(self,file_name):
        """ Opens the file passed in as an argument """
        try:
            self.fd = open(file_name,'rb')
        except:
            print("File could not be found, please try again")
            sys.exit()
    

def usage():
    """ Prints correct usage and exits """
    print("Usage: python3.2 lab3_application.py <filename>")

def main():
    """ Simple arg check and runs """
    if len(sys.argv) != 2:
        usage()
    else:
        mw = MysteryWord()
        mw.open_file(sys.argv[1])
        mw.get_info()
        mw.find_word()

# Standard boilerplate to run main()
if __name__ == '__main__':
    main()