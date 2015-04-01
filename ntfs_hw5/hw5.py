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
        self.mft_head = MFT_entry(self._mft)
        self.mft_head.run()
        self.find_entry()

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
        self._mft_start = self._mft_start * self._bytes_per_sector * self._sectors_per_cluster

        print ("MFT Start: %d" % self._mft_start)
        print ("")

    def read_in_mft(self):
        """
        """

        self._fd.seek(self._mft_start)
        self._mft = self._fd.read(1024)

    def find_entry(self):
        entry = 32
        print (len(self.mft_head._runlist))
        constant = len(self.mft_head._runlist)//1024
        print (constant)
        entry = entry // constant
        print(entry)
        entry_start = self.mft_head._runlist[entry]
        print (entry_start)
        entry_start = entry_start * self._bytes_per_sector * self._sectors_per_cluster
        print (entry_start)
        self._fd.seek(entry_start)
        mft = self._fd.read(1024)
        print (bytes.decode(mft[0:8]))
        entry = MFT_entry(mft)
        #entry.run()

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
        self._used_size = 0
        self._next_attrID = 0
        self._runlist = []

    def run(self):
        self.istat()
        self.fix_up()
        self.parse_attributes()

    def istat(self):

        # get the sequence value of the entry
        seq = unpack("<B", self._mft[16:17])[0]

        # get the logfile sequence number (lsn) of the entry
        lsn = unpack("<2L", self._mft[8:16])[0]

        # get used size of the entry
        self._used_size = unpack("<L", self._mft[24:28])[0]

        # get allocated size of the entry
        allocated_size = unpack("<L", self._mft[28:32])[0]

        # get offset to first attribute
        self._first_attr = unpack("<H", self._mft[20:22])[0]

        # get next attribute id
        self._next_attrID = unpack("<H", self._mft[40:42])[0]

        print ("MFT Entry Header Values:")
        print ("Sequence: %d" % seq)
        print ("$LogFile Sequence Number: %d" % lsn)
        print ("Allocated/Unallocated File")
        print ("Directory")
        print ("")
        print ("Used size: %d bytes" % self._used_size)
        print ("Allocated size: %d bytes" % allocated_size)
        print ("")

    def fix_up(self):
        """
        Handle the fix up array
        """

        # get the offset to the fix up array
        offset = unpack("<H", self._mft[4:6])[0]
        print ("Offset to fix up array: %d" % offset)

        # get the number of entries in the fix up array
        num = unpack("<H", self._mft[6:8])[0]
        print ("Number of entries in the fix up array: %d" % num)

        signature = ''.join('{:02x}'.format(b) for b in reversed(self._mft[offset:offset+2]))
        print ("Fixup sig: 0x" + signature)

        fixup_array = []
        string = ""
        for i in range (0, num-1):
            fixup_array.append(self._mft[offset+2+i*2: offset+4+i*2])
            string += "0x" + ''.join('{:02x}'.format(b) for b in reversed(fixup_array[i])) + ", "

        print("Fixup array: [%s]" % string)

        temp_mft = []
        current_offset = 0
        print (self._mft[510:512])
        print (self._mft[1022:1024])
        for i in range (0, num-1):
            sector_offset = 510*(i+1) + i*2
            bytes = "0x" + ''.join('{:02x}'.format(b) for b in reversed(self._mft[sector_offset:sector_offset+2]))
            print ("Bytes %d/%d %s" % (sector_offset, sector_offset+1, bytes))

            # over write
            print ("Overwriting %s into bytes %d/%d" % 
                (fixup_array[i], sector_offset, sector_offset+1))
            temp_mft.extend(self._mft[current_offset:sector_offset])
            temp_mft.extend(fixup_array[i])
            fixup_array[i] = self._mft[sector_offset:sector_offset+2]
            current_offset = sector_offset+2

        print (fixup_array)

        temp_mft = bytearray(temp_mft)
        print (temp_mft[510:512])
        print (temp_mft[1022:1024])
        print (temp_mft)
        self._mft = temp_mft

        print ("")

    def parse_attributes(self):
        """
        """
        #print ("Next attr id %d" % self._next_attrID)
        byte_offset = self._first_attr
        used_size = self._used_size - 56
        attr_count = 0
        while (byte_offset < used_size and attr_count < self._next_attrID):
            # read in first/next attribute
            attr_size = unpack("<L", self._mft[byte_offset+4:byte_offset+8])[0]
            attr = self._mft[byte_offset:byte_offset+attr_size]

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
                standard_info = STD_INFO(attr)
                standard_info.parse()

            # if type is 48, parse file_name
            elif attr_type == 48:
                file_name = FILE_NAME(attr)
                file_name.parse()


            # if it is a resident attribute
            elif nr_flag == 0:
                # get size of content
                content_size = unpack("<L", attr[16:20])[0]
                print ("\tcontent size \t %d" % content_size)
                # get offset to content
                content_offset = unpack("<H", attr[20:22])[0]
                print ("\tcontent offset \t %d" % content_offset)

            # if it is a non-resident attribute
            elif nr_flag == 1:
                start_vcn = unpack("<2L", attr[16:24])[0]
                end_vcn = unpack("<2L", attr[24:32])[0]
                print ("VCN: %d - %d" % (start_vcn, end_vcn))

                # get offset to runlist 32-33
                offset_to_rl = unpack("<H", attr[32:34])[0]
                print ("Start of RL = %d" % offset_to_rl)
                self.parse_runlist(attr, attr_type, offset_to_rl)

            # set up for next attribute
            byte_offset += attr_size
            attr_count += 1
            print ("")
            # end while loop

    def parse_runlist(self, attr, attr_type, offset):
        """
        """

        first_byte = attr[offset:offset+1] # read first byte
        offset += 1
        prev_rl_offset = 0

        while (first_byte != b"\x00"): # indicates end of rl
            print ("First byte: 0x" + ''.join('{:x}'.format(b) for b in reversed(first_byte)))

            # get offset field by shifting byte to get the first 4 nibbles
            offset_field = unpack("<B", first_byte)[0] >> 4
            print ("Length of offset field: %d" % offset_field)

            # get runlist field by masking to get the second 4 nibbles
            rl_field = unpack("<B", first_byte)[0] & 0b00001111
            print ("Length of RL field: %d" % rl_field)

            # get the length of the runlist
            rl_length = getSigned(attr[offset:offset+rl_field])
            offset += rl_field
            print ("Runlist length: %d" % rl_length)

            # get the runlist offset
            rl_offset = getSigned(attr[offset:offset+offset_field])
            offset += offset_field
            print ("Runlist offset: %d" % rl_offset)

            start_cluster = prev_rl_offset + rl_offset
            end_cluster = start_cluster + rl_length-1
            print ("Clusters go from: %d - %d" % (start_cluster, end_cluster))
            if attr_type == 128: 
                self._runlist.extend(range(start_cluster, end_cluster))
                #print (self._runlist)

            # set up for next item in the runlist
            prev_rl_offset = rl_offset
            first_byte = attr[offset:offset+1]
            offset += 1
            print ("")


class STD_INFO(object):
    """
    Parses the $STD_INFO attribute of the $MFT.
    """

    def __init__(self, attribute):
        self._attr = attribute


    def parse(self):
        print ("Parsing STANDARD_INFO")

        # get size of content 16-19
        self._content_size = unpack("<L", self._attr[16:20])[0]
        # get offset to content 20-21
        self._content_offset = unpack("<H", self._attr[20:22])[0]

        # read in content
        self._content = self._attr[self._content_offset:self._content_size
            +self._content_offset]

        # get creation time 0-7
        self._creation = convert_time(self._content[0:8])
        # get file altered time 8-15
        self._file_altered = convert_time(self._content[8:16])
        # get MFT altered time 16-23
        self._mft_altered = convert_time(self._content[16:24])
        # get file accessed time 24-31
        self._file_accessed = convert_time(self._content[24:32])
        # get flags 32-35
        self._flags = unpack("<L", self._content[32:36])[0]
        # get maximum number of versions 36-39
        self._num_versions = unpack("<L", self._content[36:40])[0]
        # get version number 40-43
        self._version = unpack("<L", self._content[40:44])[0]
        # get class id 44-47
        self._class_id = unpack("<L", self._content[44:48])[0]
        # get owner id 48-51
        self._owner_id = unpack("<L", self._content[48:52])[0]
        # get security id 52-55
        self._security_id = unpack("<L", self._content[52:56])[0]
        # get quota charged 56-63
        self._quota = unpack("<2L", self._content[56:64])[0]
        # update sequence number 64-71
        self._usn = unpack("<2L", self._content[64:72])[0]

        self.print_fields()

    def print_fields(self):
        print ("\t creation time \t %s" % self._creation)
        print ("\t  file altered \t %s" % self._file_altered)
        print ("\t   mft altered \t %s" % self._mft_altered)
        print ("\t file accessed \t %s" % self._file_accessed)
        print ("\t         flags \t %s" % self._flags)
        print ("\tmax # versions \t %s" % self._num_versions)
        print ("\tversion number \t %s" % self._version)
        print ("\t      Class ID \t %s" % self._class_id)
        print ("\t      Owner ID \t %s" % self._owner_id)
        print ("\t   Security ID \t %s" % self._security_id)
        print ("\t Quota Charged \t %s" % self._quota)
        print ("\t  Update seq # \t %s" % self._usn)


class FILE_NAME(object):
    """
    Parses the $FILE_NAME attribute in the $MFT.
    """

    def __init__(self, attribute):
        self._attr = attribute

    def parse(self):
        print ("Parsing FILE_NAME")

        # get size of content 16-19
        self._content_size = unpack("<L", self._attr[16:20])[0]
        # get offset to content 20-21
        self._content_offset = unpack("<H", self._attr[20:22])[0]

        # read in content
        self._content = self._attr[self._content_offset:self._content_size
            +self._content_offset]

        # get file reference of parent directory 0-7
        self._parent_dir = unpack("<2L", self._content[0:8])[0]
        # get file creation time 8-15
        self._file_creation = convert_time(self._content[8:16])
        # get file modification time 16-23
        self._file_modification = convert_time(self._content[16:24])
        # get MFT modification time 24-31
        self._mft_modification = convert_time(self._content[24:32])
        # get file access time 32-39
        self._file_access = convert_time(self._content[32:40])
        # get allocated size of the file 40-47
        self._alloc_size = unpack("<2L", self._content[40:48])[0]
        # get real size of the file 48-55
        self._real_size = unpack("<2L", self._content[48:56])[0]
        # get flags 56-59
        self._flags = unpack("<L", self._content[56:60])[0]
        # get reparse value 60-63
        self._reparse = unpack("<L", self._content[60:64])[0]
        # get length of name 64-64
        self._name_length = unpack("<B", self._content[64:65])[0]
        # get namespace 65-65
        self._namespace = unpack("<B", self._content[65:66])[0]
        # get name 66+
        #self._name = unpack("<")

        self.print_fields()

    def print_fields(self):
        print ("\t  content Size \t %d" % self._content_size)
        print ("\t    Parent dir \t %d" % self._parent_dir)
        print ("    file creation time \t %s" % self._file_creation)
        print ("\t file mod time \t %s" % self._file_modification)
        print ("\t  MFT mod time \t %s" % self._mft_modification)
        print ("      file access time \t %s" % self._file_access)
        print ("   Alloc. size of file \t %d" % self._alloc_size)
        print ("\t Real filesize \t %d" % self._real_size)
        print ("\t         flags \t %d" % self._flags)
        print ("\t Reparse value \t %d" % self._reparse)
        print ("\t       NameLen \t %d" % self._name_length)
        print ("\t     Namespace \t %d" % self._namespace)


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



