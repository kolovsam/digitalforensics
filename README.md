##UMass Amherst CS365: Digital Forensics

All homeworks written in Python 3.2

####Homework 1: Hexdump
  
  Output mirrors basic output of "/usr/bin/hexdump -vC filename"
  ```
    00000000  67 49 00 00 78 00 00 00  00 00 00 08 04 00 00 00  |gI..x...........|
    00000010  01 00 00 00 f8 04 00 00  08 05 00 00 18 05 00 00  |................|
    etc...
  ```
  To run `/usr/bin/python3.2 hexdump.py <filename>`

####Homework 2: Strings

  To run `/usr/bin/python3.2 strings.py <min string length> <filename>`

####Homework 3: EXIF

  Parses EXIF tags from a JPEG file.

  To run `/usr/bin/python3.2 exif.py <filename>`

####Homework 4: FAT

  Parses a FAT file system.

  To run `/usr/bin/python3.2 fstat.py <offset param> <image.dmg>`

####Homework 5: NTFS

  Parses an NTFS file system.

  To run `/usr/bin/python hw5.py <entry to parse> <image.dmg>`

####Homework 6: Zebra

  Had to use forensics techniques and sleuth kit to find evidence that the user of the example drive case.dd was looking at pictures of zebras.
