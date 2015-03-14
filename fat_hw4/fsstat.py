#!/usr/vin/env python3

"""
Sam Kolovson
CS365: Digital Forensics
Professor Brian Levine
Homework 3: EXIF
February 2015
"""

import sys
from struct import unpack


class Fat(object):
    """
    Parses the values in the Boot Sector of FAT16 image, producing
    most of the values of the fsstat program from sleuthkit.

    Variables:
        _offset (int): offset of the boot sector, taken as input
        _dmg (string): name of the image to be parsed
        _fd (file): the image being parsed
        _range (short): the total number of sectors
        _reserved (short): number of sectors in the reserved space
        _sectors_per_cluster (byte): number of sectors per cluster
        _end_fats (short):
        _cluster_area ():
        _fat_size ()
        _end_root ();
        _cluster_size ():
        _sector_size ():

    Functions:
        open_image()
        OEM_name()
        volume_id()
        volume_label()
        file_system_type()
        total_range()
        reserved()
        boot_sector()
        fats()
        data_area()
        root_dir()
        cluster_area()
        non_clustered()
        sector_size()
        cluster_size()
        cluster_range()

    """

    def __init__(self, offset, dmg):
        try:
            self._offset = int(offset)
        except:
            print("Please input number not letter...")
            print("Error:", sys.exc_info()[0])

        self._dmg = dmg
        self._fd = None
        self._fat_size = None
        self._range = None
        self._sector_size = None
        self._sectors_per_cluster = None
        self._reserved = None
        self._end_root = None
        self._cluster_area = None
        self._cluster_size = None
        self. _end_fats = None


    def run(self):
        """
        Calls all functions of Fat to print out the boot sector
        information in simillar format to TSK fstat
        """

        self.open_image()

        print ("FILE SYSTEM INFORMATION")
        print ("----------------------------------------------")
        print ("File System Type: FAT16")
        print ("\n")

        self.oem_name()
        self.volume_id()
        self.volume_label()
        print ("\n")

        self.file_system_type()
        print ("\n")

        print ("File System Layout (in sectors)")
        self.total_range()
        self.reserved()
        self.boot_sector()
        self.fats()
        self.data_area()
        self.root_dir()
        self.cluster_area()
        self.non_clustered()
        print("\n")

        print ("CONTENT INFORMATION")
        print ("----------------------------------------------")
        self.sector_size()
        self.cluster_size()
        self.cluster_range()
        print ("\n")


    def file_system_type(self):
        """
        Prints file system type

        Attributes:
            fst (string): file system type
        """

        self._fd.seek(54) # seek to the file system string
        fst = bytes.decode(self._fd.read(8)) # decode the bytes
        print ("File System Type Label: %s" % fst)


    def oem_name(self):
        """
        Prints OEM name

        Attributes:
            oem (string): OEM name
        """

        self._fd.seek(3)
        oem = bytes.decode(self._fd.read(8))
        print ("OEM Name: %s" % oem)

    def volume_id(self):
        """
        Prints Volume ID

        Attributes:
            volume_id (bytes): volume id in hex
        """

        self._fd.seek(39)
        volume_id = ''.join('{:x}'.format(b) for b in reversed(self._fd.read(4)))
        print ("Volume ID: 0x" + volume_id)


    def volume_label(self):
        """
        Prints Volume Label (Boot Sector)

        Attributes:
            volume_label (string): volume label
        """

        self._fd.seek(43)
        volume_label = bytes.decode(self._fd.read(11))
        print ("Volume Label (Boot Sector): %s" % volume_label)


    def total_range(self):
        """ Prints total range """
        self._fd.seek(19)
        self._range = unpack("<H", self._fd.read(2))[0] - 1

        if self._range == 0:
            self._fd.seek(32)
            self._range = unpack("<L", self._fd.read(4))[0] - 1

        print ("Total Range: %d - %d" % (self._offset, self._range))
        print ("Total Range in Image: %d - %d" % (self._offset, self._range - 1))


    def reserved(self):
        """ Prints sectors of reserved area """

        self._fd.seek(14)
        self._reserved = unpack("<H", self._fd.read(2))[0]
        print ("* Reserved: %d - %d" % (self._offset, self._reserved-1))


    def boot_sector(self):
        """ Prints start of boot sector """

        print ("** Boot Sector: %d" % self._offset)


    def fats(self):
        """
        Prints sectors of FATs

        Attributes:
            fats (byte): number of FATs (1 or 2)
            start_f1 (int): what sector FAT 1 starts at
        """

        # get size of fats in sectors
        self._fd.seek(22)
        self._fat_size = unpack("<H", self._fd.read(2))[0]
        self._end_fats = self._reserved + self._fat_size - 1

        print ("* FAT 0: %d - %d" % (self._reserved, self._end_fats))

        # check number of fats
        self._fd.seek(16)
        fats = unpack("<B", self._fd.read(1))[0]
        start_f1 = self._end_fats
        self._end_fats = self._end_fats + self._fat_size

        if fats == 2:
            print ("* FAT 1: %d - %d" % (start_f1, self._end_fats))


    def data_area(self):
        """ Prints the sectors of the data area """

        print ("* Data Area: %d - %d" % (self._end_fats+1, self._range))


    def root_dir(self):
        """ Prints the sectors of the root directory """

        self._end_root = self._end_fats + self._fat_size + self._reserved
        print ("** Root Directory: %d - %d" % (self._end_fats + 1, self._end_root))


    def cluster_area(self):
        """ Prints the sectors of the cluster area """

        self._fd.seek(11)
        self._sector_size = unpack("<H", self._fd.read(2))[0]

        self._fd.seek(13)
        self._sectors_per_cluster = unpack("<B", self._fd.read(1))[0]
        self._cluster_size = self._sector_size * self._sectors_per_cluster

        self._cluster_area = (self._range / self._sectors_per_cluster)
        self._cluster_area = self._cluster_area * self._sectors_per_cluster
        print ("** Cluster Area: %d - %d" % (self._end_root + 1, self._cluster_area - 1))


    def non_clustered(self):
        """ Prints the non-cluster sectors """

        print ("** Non-Clustered: %d - %d" % (self._cluster_area, self._range))


    def sector_size(self):
        """ Prints bytes per sector """

        print ("Sector Size: %d bytes" % self._sector_size)

    def cluster_size(self):
        """ Prints cluster size """

        print ("Cluster Size: %s bytes" % self._cluster_size)

    def cluster_range(self):
        """
        Prints cluster range

        Attributes:
            start (int): what cluster the cluster range starts
            end (int): what cluster the cluster range ends
        """

        start = 2
        end = (self._cluster_area - self._end_root + 1)
        end = end/self._sectors_per_cluster
        print ("Cluster Range: %d - %d" % (start, end))


    def open_image(self):
        """ Opens dmg, and calls usage() on error """
        try:
            self._fd = (open(self._dmg, "rb"))
        except IOError as err:
            print("IOError opening image: \n\t%s" % err)
            usage()
        except:
            print("Unexpected error:", sys.exc_info()[0])
            usage()


def usage():
    """ Print usage string and exit() """
    print("Usage:\n%s <offset parameter> <image.dmg>\n" % sys.argv[0])
    sys.exit()

def main():
    """ Simple arg check and runs """
    if len(sys.argv) == 3:
        fsstat = Fat(sys.argv[1], sys.argv[2])
        fsstat.run()
    else:
        usage()

# Standard boilerplate to run main()
if __name__ == '__main__':
    main()
