#!/usr/vin/env python3

"""
Sam Kolovson
CS365: Digital Forensics
Professor Brian Levine
Homework 5: NTFS
March 2015
"""

import sys
from struct import unpack
import datetime

class NTFS(object):
    """
    """

    def __init__(self, dmg):
        self._dmg = dmg
        self._fd = None


    def run(self):
        self.open_image()
        self.find_MFT()
        self.read_in_mft()
        mft_head = MFT_entry(self._mft)
        mft_head.istat()
        mft_head.fix_up()
        mft_head.parse_attributes()


    def find_MFT(self):
        """
        Finds the starting cluster address of the MFT.
        """

        # get the number of bytes per sector from the boot sector
        self._fd.seek(11)
        self._bytes_per_sector = unpack("<H", self._fd.read(2))[0]
        print ("Bytes per Sector: %d" % self._bytes_per_sector)

        # get the number of sectors per cluster from the boot sector
        self._sectors_per_cluster = unpack("<B", self._fd.read(1))[0]
        print ("Sectors per Cluster: %d" % self._sectors_per_cluster)

        # get the start of the $MFT 
        self._fd.seek(48)
        self._mft_start = unpack("<2L", self._fd.read(8))[0]
        self._mft_start = self._mft_start * self._bytes_per_sector

        print ("MFT Start: %d" % self._mft_start)
        print ("")


    def read_in_mft(self):
        """
        """

        self._fd.seek(self._mft_start)
        self._mft = self._fd.read(1024)


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


class MFT_entry(object):
    """
    Parses an MFT entry.
    """

    def __init__(self, mft):
        #self._fd = fd
        self._mft = mft
        self._first_attr = 0


    def istat(self):

        # get the sequence value of the entry
        #self._fd.seek(self._mft + 16)
        seq = unpack("<B", self._mft[16:17])[0]

        # get the logfile sequence number (lsn) of the entry
        #self._fd.seek(self._mft + 8)
        lsn = unpack("<2L", self._mft[8:16])[0]

        # get used size of the entry
        #self._fd.seek(self._mft + 24)
        used_size = unpack("<L", self._mft[24:28])[0]

        # get allocated size of the entry
        allocated_size = unpack("<L", self._mft[28:32])[0]

        # get offset to first attribute
        #self._fd.seek(self._mft + 20)
        self._first_attr = unpack("<H", self._mft[20:22])[0]

        print ("MFT Entry Header Values:")
        print ("Sequence: %d" % seq)
        print ("$LogFile Sequence Number: %d" % lsn)
        print ("Allocated/Unallocated File")
        print ("Directory")
        print ("")
        print ("Used size: %d bytes" % used_size)
        print ("Allocated size: %d bytes" % allocated_size)
        print ("")


    def fix_up(self):
        """
        Handle the fix up array
        """

        # get the offset to the fix up array
        #self._fd.seek(self._mft + 4)
        offset = unpack("<H", self._mft[4:6])[0]
        print ("Offset to fix up array: %d" % offset)

        # get the number of entries in the fix up array
        num = unpack("<H", self._mft[6:8])[0]
        print ("Number of entries in the fix up array: %d" % num)

        #self._fd.seek(self._mft + offset)
        signature = ''.join('{:02x}'.format(b) for b in reversed(self._mft[offset:offset+2]))
        print ("Fixup sig: 0x" + signature)

        fixup_array = []
        string = ""
        for i in range (0, num):
            fixup_array.append(self._mft[offset+2+i*2: offset+4+i*2]) #self._fd.read(2))
            string += "0x" + ''.join('{:02x}'.format(b) for b in reversed(fixup_array[i])) + ", "

        print("Fixup array: [%s]" % string)

        for i in range (0, num):
            sector_offset = 510*(i+1) + i*2
            #self._fd.seek(self._mft + sector_offset)
            bytes = "0x" + ''.join('{:02x}'.format(b) for b in reversed(self._mft[sector_offset:sector_offset+2]))#self._fd.read(2)))
            print ("Bytes %d/%d %s" % (sector_offset, sector_offset+1, bytes))

            # over write
            print ("Overwriting %s into bytes %d/%d" % 
                (fixup_array[i], sector_offset, sector_offset+1))
            #print (self._mft[sector_offset:sector_offset+2])
            #print (fixup_array[i])
            #self._mft[sector_offset:sector_offset+2] = fixup_array[i]

        print ("")


    def parse_attributes(self):
        """
        """

        # read in first attribute
        attr_size = unpack("<L", self._mft[self._first_attr+4:self._first_attr+8])[0]
        attr = self._mft[self._first_attr:attr_size+self._first_attr]

        # parse attribute header
        # get attribute type identifier 0-3
        attr_type = unpack("<L", attr[0:4])[0]
        # get non-resident flag 8-8
        nr_flag = unpack("<B", attr[8:9])[0]
        if nr_flag == 0: resident = "Resident"
        else: resident = "Non-resident" 
        # get length of name 9-9
        name_length = unpack("<B", attr[9:10])[0]
        # get offset to name 10-11
        name_offset = unpack("<H", attr[10:12])[0]
        # get flags 12-13
        flags = unpack("<H", attr[12:14])[0]
        # get attribute identifier 14-15
        attr_id = unpack("<H", attr[14:16])[0]

        # print attribute header
        print ("Type: %d, %s, size: %d, " % (attr_type, resident, attr_size), end="")
        print ("NameLen: %d, NameOff: %d, " % (name_length, name_offset), end="")
        print ("Flags: %d, Attribute id: %d" % (flags, attr_id))


        # if type is 16, parse std_info
        if attr_type == 16:
            standard_info = std_info(attr)
            standard_info.parse()

        # if type is 48, parse file_name
        #if attr_type == 48:
        #   file_name = file_name()
        #   file_name.parse()


        # if it is a resident attribute

        # get size of content
        # get offset to content


        # if it is a non-resident attribute

        # get offset to runlist 32-33
        # get actual size of attribute content 


class std_info(object):
    """
    """

    def __init__(self, attribute):
        self._attr = attribute


    def parse(self):
        print ("Parsing STANDARD_INFO")

        # get size of content 16-19
        content_size = unpack("<L", self._attr[16:20])[0]
        # get offset to content 20-21
        content_offset = unpack("<H", self._attr[20:22])[0]

        # read in content
        content = self._attr[content_offset:content_size+content_offset]

        # get creation time 0-7
        creation = convert_time(content[0:8])
        # get file altered time 8-15
        file_altered = convert_time(content[8:16])
        # get MFT altered time 16-23
        mft_altered = convert_time(content[16:24])
        # get file accessed time 24-31
        file_accessed = convert_time(content[24:32])
        # get flags 32-35
        flags = unpack("<L", content[32:36])[0]
        # get maximum number of versions 36-39
        num_versions = unpack("<L", content[36:40])[0]
        # get version number 40-43
        version = unpack("<L", content[40:44])[0]
        # get class id 44-47
        class_id = unpack("<L", content[44:48])[0]
        # get owner id 48-51
        owner_id = unpack("<L", content[48:52])[0]
        # get security id 52-55
        security_id = unpack("<L", content[52:56])[0]
        # get quota charged 56-63
        quota = unpack("<2L", content[56:64])[0]
        # update sequence number 64-71
        usn = unpack("<2L", content[64:72])[0]

        print ("creation time  %s" % creation)
        print ("file altered  %s" % file_altered)
        print ("mft altered  %s" % mft_altered)
        print ("file accessed  %s" % file_accessed)
        print ("flags  %s" % flags)
        print ("max # versions  %s" % num_versions)
        print ("version number  %s" % version)
        print ("Class ID  %s" % class_id)
        print ("Owner ID  %s" % owner_id)
        print ("Security ID  %s" % security_id)
        print ("Quota Charged %s" % quota)
        print ("Update seq #  %s" % usn)


def convert_time(time):
    D = 116444736000000000
    time = getSigned(time)
    epoch = (time - D)/10000000
    return str(datetime.datetime.fromtimestamp(epoch))


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
    #print ("len: %d" %length)

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

    else:
        return unpack("<q", bytes)[0]



def usage():
    """ Print usage string and exit() """
    print("Usage:\n%s <image.dmg>\n" % sys.argv[0])
    sys.exit()

def main():
    """ Simple arg check and runs """
    if len(sys.argv) == 2:
        istat = NTFS(sys.argv[1])
        istat.run()
    else:
        usage()

# Standard boilerplate to run main()
if __name__ == '__main__':
    main()



