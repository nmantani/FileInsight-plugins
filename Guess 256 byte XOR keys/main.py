#
# Guess 256 byte XOR keys - Guess 256 byte XOR keys from selected region (the
# whole file if not selected) based on the byte frequency
#
# Copyright (c) 2013, Nobutaka Mantani
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

import sys
import hashlib
import binascii
import struct

def xor256(buf, key):
    b = list(buf)
    k = list(key)
    length = len(buf)
    for i in range(0, length):
        b[i] = chr(ord(b[i]) ^ ord(k[i % 256]))
    return  "".join(b)

def find_ole_header(buf, offset):
    i = 0
    pos = 0
    found = 0
    length = len(buf)
    while i < length:
        pos = buf.find("".join(['\xd0', '\xcf', '\x11', '\xe0', '\xa1', '\xb1', '\x1a', '\xe1']), i)
        if pos == -1:
            break
        else:
            print "OLE2 Compound Document header found at offset %s" % hex(offset + pos)
            setBookmark(offset + pos, 8, hex(offset + pos), "#c8ffff")
            i += pos + 8
            found += 1
    return found

def find_pdf_header(buf, offset):
    i = 0
    pos = 0
    found = 0
    length = len(buf)
    while i < length:
        pos = buf.find("%PDF", i)
        if pos == -1:
            break
        else:
            print "PDF header found at offset %s" % hex(offset + pos)
            setBookmark(offset + pos, 4, hex(offset + pos), "#c8ffff")
            i += pos + 4
            found += 1
    return found

def find_pe_header(buf, offset):
    i = 0
    pos = 0
    found = 0
    length = len(buf)
    while i < length:
        pos = buf.find("MZ", i)
        if pos == -1:
            break
        else:
            if pos + 64 < length:
                # Get the offset of the "PE" characters
                pe_offset = struct.unpack("<I", buf[pos+60:pos+64])[0]
                if pos + pe_offset + 23 < length:
                    # Check machine
                    if buf[pos+pe_offset:pos+pe_offset+6] == "".join(['P', 'E', '\x00', '\x00', '\x4c', '\x01']):
                        # Check characteristics
                        if struct.unpack("B", buf[pos+pe_offset+23])[0] & 0x20:
                            print "Win32 DLL found at offset %s" % hex(offset + pos)
                        else:
                            print "Win32 executable found at offset %s" % hex(offset + pos)
                        setBookmark(offset + pos, 2, hex(offset + pos), "#c8ffff")
                        found += 1
                    elif buf[pos+pe_offset:pos+pe_offset+6] == "".join(['P', 'E', '\x00', '\x00', '\x64', '\x86']):
                        # Check characteristics
                        if struct.unpack("B", buf[pos+pe_offset+23])[0] & 0x20:
                            print "Win64 DLL found at offset %s" % hex(offset + pos)
                        else:
                            print "Win64 executable found at offset %s" % hex(offset + pos)
                        setBookmark(offset + pos, 2, hex(offset + pos), "#c8ffff")
                        found += 1
            i += pos + 2
    return found

def find_rtf_header(buf, offset):
    i = 0
    pos = 0
    found = 0
    length = len(buf)
    while i < length:
        pos = buf.find("{\\rtf", i)
        if pos == -1:
            break
        else:
            print "RTF header found at offset %s" % hex(offset + pos)
            setBookmark(offset + pos, 5, hex(offset + pos), "#c8ffff")
            i += pos + 5
            found += 1
    return found

length = getSelectionLength()
offset = getSelectionOffset()

if (length > 0):
    buf = getSelection()
    print "Top five 256 byte XOR keys guessed from offset %s to %s\n" % (hex(offset), hex(offset + length - 1))
else:
    offset = 0
    buf = getDocument()
    length = getLength()
    print "Top five 256 byte XOR keys guessed from the whole file\n"

block = {}
freq = {}
for i in range(0, length, 256):
    b = buf[i:i + 256]
    if len(b) == 256:
        h = hashlib.md5(b).hexdigest()
        if h not in block:
            block[h] = b
            freq[h] = 1
        else:
            freq[h] += 1

i = 0
for k, v in sorted(freq.items(), key=lambda x:x[1], reverse=True):
    if i < 5:
        sys.stdout.write("XOR key: 0x")
        for j in range(255, -1, -1):
            sys.stdout.write("%02x" % ord(block[k][j]))
        print
        print "Occurrence count: %i" % v
        tmp = xor256(buf, block[k])
        num_pe = find_pe_header(tmp, offset)
        num_ole = find_ole_header(tmp, offset)
        num_pdf = find_pdf_header(tmp, offset)
        num_rtf = find_rtf_header(tmp, offset)
        if num_pe + num_ole + num_pdf + num_rtf == 1:
            print "Added a bookmark to the search hit."
        elif num_pe + num_ole + num_pdf + num_rtf > 1:
            print "Added bookmarks to the search hits."
        print
        i += 1

