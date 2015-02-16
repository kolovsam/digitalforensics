#!/usr/bin/env python3

"""
Sam Kolovson
CS365: Digital Forensics
Professor Brian Levine
Homework 3: EXIF
February 2015
"""

import sys
from struct import unpack

class Exif(object):
    """
    Parses EXIF tags from a JPEG file
    """
    def __init__(self, filename):
        self._filename = filename
        self._fd = None
        self._markers = []
        self._sizes = []

    def run(self):
        """
        Run functions
        """
        self.open_file()
        self.verify_jpeg()  # part 1 (5pts)
        self.find_markers() # part 2 (10pts)
        self.find_exif_header() # part 3 (10pts)
        self.confirm_big_endian() # part 3 cont.
        #self.find_IFDstart() # part 4 (10pts)
        #self.print_entries() # part 5 (20pts)

    def verify_jpeg(self):
        """
        Varifies that the file is JPEG by confirming that the first
        2 bytes of the file ar 0xffd8
        """
        # read first two bytes of the file
        _jpeg = self._fd.read(2)

        # should be 0xffd8...
        if _jpeg == b"\xff\xd8":
            print ("%s is a JPEG file." % self._filename)
        # else its not a jpeg file...
        else:
            print ("%s is NOT a JPEG file." % self._filename)
            print ("The program will exit.")
            sys.exit()

    def find_markers(self):
        """
        Finds each marker, prints its location from the start of the
        file, the marker number, and its length. Stop when 0xFFDA
        marker is reached. This marks the start of actualy image
        data.

        Each marker begins: 0xFFmmdddd, where mm is the marker number
        (ex. E0), and dddd is the length of the marker including the
        two bytes of 0xFFmm. 

        """

        marker = 0
        size = 0

        while marker != b"\xff\xda":
            # read in marker
            marker = self._fd.read(2)
            
            # read in size
            size = self._fd.read(2)
            
            # print [location] Marker 0xmarker size = 0xsize
            marker_str = ''.join('{:02X}'.format(b) for b in marker)
            size_str = ''.join('{:02X}'.format(b) for b in size)
            print ("[0x%04X] Marker 0x%s size=0x%s" % 
                (self._fd.tell(), marker_str, size_str))

            # add location of marker
            self._markers.append(self._fd.tell())

            # unpack size as a short
            size = unpack(">H", size)[0]
            self._sizes.append(size)

            # seek to next marker
            self._fd.seek(size-2, 1)


    def find_exif_header(self):
        """
        Locates the EXIF header.
        """

        for marker in self._markers:
            self._fd.seek(marker)
            exif = self._fd.read(6)

            if exif == b"Exif\x00\x00":
                print ("Found an EXIF header!")
                return

        # didn't find exif header
        print ("Did not find an EXIF header.")
        sys.exit()


    def confirm_big_endian(self):
        """
        Confirms Exif entries are big endian If it is little endian, 
        the program will exit.
        """

        endian = self._fd.read(4)

        # exit if it is not big endian
        if endian != b"MM\x00\x2a":
            print ("This image is little endian.")
            print ("The program will now exit.")
            sys.exit()
        else:
            print ("This image is big endian!")

    def find_IFDstart(self):
        """
        In the marker with confirmed EXIF data, find the start of
        the IFD and print then number of entries.
        """
        # after confirming big endian, fd.tell points to the idf_offset
        ifd_offset = unpack(">L", self._fd.read(4))

        # seek to the start of the IFD
        self._fd.seek(ifd_offset-8, 1)


        # get number of entries


    #def print_entries(self):


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


def usage():
    """ Print usage string and exit() """
    print("Usage:\n%s <filename>\n" % sys.argv[0])
    sys.exit()

def main():
    """ Simple arg check and runs """
    if len(sys.argv) == 2:
        exif = Exif(sys.argv[1])
        exif.run()
    else:
        usage()

# Standard boilerplate to run main()
if __name__ == '__main__':
    main()
