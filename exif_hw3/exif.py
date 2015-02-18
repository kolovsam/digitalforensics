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
from tags import TAGS

class Exif(object):
    """
    Parses EXIF tags from a JPEG file
    """
    def __init__(self, filename):
        self._filename = filename
        self._fd = None
        self._markers = []
        self._sizes = []
        self._4d = 0
        self._num_entries = 0
        self._entries_start = 0

    def run(self):
        """
        Run functions
        """
        self.open_file()
        self.verify_jpeg()  # part 1 (5pts)
        self.find_markers() # part 2 (10pts)
        self.find_exif_header() # part 3 (10pts)
        self.confirm_big_endian() # part 3 cont.
        self.find_IFDstart() # part 4 (10pts)
        self.print_entries() # part 5 (20pts)

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
        self._4d = self._fd.tell()

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
        ifd_offset = unpack(">L", self._fd.read(4))[0]


        # seek to the start of the IFD
        self._fd.seek(ifd_offset-8, 1)


        # get number of entries
        self._num_entries = unpack(">H", self._fd.read(2))[0]
        print ("Number of IFD Entries: %d" % self._num_entries)

        # set start of entries
        self._entries_start = self._fd.tell()
        #print (self._entries_start)


    def print_entries(self):
        """
        Print name in hex and string equivalent for each entry if
        the format is 1, 2, 3, 4, 5, or 7. All other types will be
        ignored. 
        """
        bytes_per_component = (0,1,1,2,4,8,1,1,2,4,8,4,8)

        # run through all entries (12 bytes each)
        for i in range(0, self._num_entries):
            self._fd.seek(i*12, 1)
            
            # tag (2 bytes)
            tag = TAGS[unpack(">H", self._fd.read(2))[0]]
            
            # format (2 bytes)
            form = unpack(">H", self._fd.read(2))[0]

            # components (4 bytes)
            components = unpack(">L", self._fd.read(4))[0]

            # length = bytes_per_component[format]*components
            length = bytes_per_component[form]*components

            # data (4 bytes)
            data = self._fd.read(4)

            if length <= 4:
                self.print_value(form, components, length, data)
            else:
                self._fd.seek(self._4d+unpack(">L", data)[0])
                self.print_value(form, components, length, self._fd.read(length))

            self._fd.seek(self._entries_start)

    def print_value(self, form, components, length, data):
        """
        Print value of IFD entry according to format.
        """
        # Unsigned byte
        if form == 1:
            print (unpack(">B", data[0:1])[0])

        # ASCII string
        elif form == 2:
            print (bytes.decode(data[0:length]))

        # Unsigned short
        elif form == 3:
            print (unpack(">%dH" % components, data[0:length])[0])

        # Unsigned long
        elif form == 4:
            print (unpack(">L", data[0:4])[0])

        # Unsigned rational
        elif form == 5:
            (numerator, denominator) = unpack(">LL", data[0:8])
            print ("%s/%s" % (numerator, denominator))

        # Undefined (raw)
        elif form == 7:
            value = unpack(">%dB" % length, data[0:length])
            print ("".join("%c" % x for x in value))


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
