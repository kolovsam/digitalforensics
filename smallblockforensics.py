#!/usr/bin/env python3

"""
160TiB of data, looking for 512GiB file, how many samples if each sample
is 4096bytes?
"""

N = 42949672960  # (160*(2^40))/4096
M = 134217728  # 512 GiB / 4096
n = 2950

i = 1
product = 1
while (i < n):
	numerator = (N - (i - 1)) - M
	denom = N - (i - 1)
	product *= numerator/denom
	i += 1

print (product)
print (product * 100)
