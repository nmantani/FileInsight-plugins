#
# Find PE file: Find PE file from selected region (the whole file if not selected)
#
# Copyright (c) 2020, Nobutaka Mantani
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
# IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
# EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
# OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
# OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
# ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import binascii
import struct
import sys

try:
    import pefile
except ImportError:
    exit(-1)

# Receive data
data = binascii.a2b_hex(sys.stdin.read())

offset = int(sys.argv[1])
i = 0
pos = 0
found = 0
valid_pe = False
length = len(data)
while i < length:
    pos = data.find(b'MZ', i)
    if pos == -1:
        break
    else:
        if pos + 64 < length:
            # Get the offset of the "PE" characters
            pe_offset = struct.unpack("<I", data[pos+60:pos+64])[0]
            if pos + pe_offset + 23 < length:
                # Check machine
                if data[pos+pe_offset:pos+pe_offset+6] == b"PE\x00\x00\x4c\x01":
                    # Check characteristics
                    if data[pos+pe_offset+23] & 0x20:
                        print("Win32 DLL found at offset %s " % hex(offset + pos), end="")
                    else:
                        print("Win32 executable found at offset %s " % hex(offset + pos), end="")
                    valid_pe = True
                elif data[pos+pe_offset:pos+pe_offset+6] == b"PE\x00\x00\x64\x86":
                    # Check characteristics
                    if data[pos+pe_offset+23] & 0x20:
                        print("Win64 DLL found at offset %s " % hex(offset + pos), end="")
                    else:
                        print("Win64 executable found at offset %s " % hex(offset + pos), end="")
                    valid_pe = True

                if valid_pe == True:
                    pe = pefile.PE(data=data[pos:], fast_load=True)
                    pe_size = pe.OPTIONAL_HEADER.SizeOfHeaders
                    for section in pe.sections:
                        pe_size += section.SizeOfRawData
                    print("size %d bytes" % pe_size)
                    if pos + pe_size > length:
                        print("The end of PE file (offset %s) is beyond the end of search region (offset %s). Bookmarked region will be truncated." % (hex(offset+pos+pe_size), hex(offset+length)))
                        #fi.setBookmark(offset + pos, length - pos, hex(offset + pos), "#c8ffff")
                    else:
                        pass
                        #fi.setBookmark(offset + pos, pe_size, hex(offset + pos), "#c8ffff")
                    found += 1
    valid_pe = False
    i = pos + 2
exit(found)
