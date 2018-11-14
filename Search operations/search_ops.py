#
# Search operations 
#
# Copyright (c) 2018, Nobutaka Mantani
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
import pefile
import re
import struct

def find_pe(fi, buf, offset):
    """
    Used by find_pe_file()
    """
    i = 0
    pos = 0
    found = 0
    valid_pe = False
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
                            print "Win32 DLL found at offset %s" % hex(offset + pos),
                        else:
                            print "Win32 executable found at offset %s" % hex(offset + pos),
                        valid_pe = True
                    elif buf[pos+pe_offset:pos+pe_offset+6] == "".join(['P', 'E', '\x00', '\x00', '\x64', '\x86']):
                        # Check characteristics
                        if struct.unpack("B", buf[pos+pe_offset+23])[0] & 0x20:
                            print "Win64 DLL found at offset %s" % hex(offset + pos),
                        else:
                            print "Win64 executable found at offset %s" % hex(offset + pos),
                        valid_pe = True
                    
                    if valid_pe == True:
                        pe = pefile.PE(data=buf[pos:], fast_load=True)
                        pe_size = pe.OPTIONAL_HEADER.SizeOfHeaders
                        for section in pe.sections:
                            pe_size += section.SizeOfRawData
                        print "size %d bytes" % pe_size
                        if pos + pe_size > length:
                            print "The end of PE file (offset %s) is beyond the end of search region (offset %s). Bookmarked region will be truncated." % (hex(offset+pos+pe_size), hex(offset+length))
                            fi.setBookmark(offset + pos, length - pos, hex(offset + pos), "#c8ffff")
                        else:
                            fi.setBookmark(offset + pos, pe_size, hex(offset + pos), "#c8ffff")
                        found += 1
        valid_pe = False
        i = pos + 2
    return found

def find_pe_file(fi):
    """
    Find PE file from selected region (the whole file if not selected)
    """
    length = fi.getSelectionLength()
    offset = fi.getSelectionOffset()

    if (length > 0):
        buf = fi.getSelection()
        found = find_pe(fi, buf, offset)
        if found > 0:
            print "%d PE file(s) found from offset %s to %s." % (found, hex(offset), hex(offset + length - 1))
            print "Added bookmark(s) to the found PE file(s)."
        else:
            print "No PE file found from offset %s to %s." % (hex(offset), hex(offset + length - 1))
    else:
        offset = 0
        buf = fi.getDocument()
        length = fi.getLength()
        found = find_pe(fi, buf, offset)
        if found > 0:
            print "%d PE file(s) found from the whole file." % found
            print "Added bookmark(s) to the found PE file(s)."
        else:
            print "No PE file found from the whole file."

def mask(x):
    """
    Masking bits
    Used by xor_hex_search() and xor_text_search()
    """
    if (x >= 0):
        return 2 ** x - 1
    else:
        return 0

def ror(x, rot=1):
    """
    Bitwise rotate right
    Used by xor_hex_search() and xor_text_search()
    """
    rot %= 8
    if (rot < 1):
        return x
    x &= mask(8)
    return (x >> rot) | ((x << (8 - rot)) & mask(8))

def rol(x, rot=1):
    """
    Bitwise rotate left
    Used by xor_hex_search() and xor_text_search()
    """
    rot %= 8
    if (rot < 1):
        return x
    x &= mask(8)
    return ((x << rot) & mask(8)) | (x >> (8 - rot))

def valdict(buf):
    """
    Make dictionary of values in data
    Used by xor_hex_search() and xor_text_search()
    """
    values = {}
    b = list(buf)
    length = len(b)

    for i in range(0, length):
        v = ord(buf[i])
        if (v not in values):
            values[v] = True

    return values

def search_xor_hex(fi, buf, offset, length, keyword):
    """
    Search XORed string
    Used by xor_hex_search()
    """
    LEN_AFTER_HIT = 30

    values = valdict(buf)
    num_hits = 0

    for i in range(0, length):
        v = ord(buf[i])
        if (v not in values):
            values[v] = True

    for i in range(0, 256):
        pattern = keyword[:]
        notinvalues = False
        hits = []

        # Encode search string and check whether the values of encoded string exist in data
        for j in range(0, len(pattern)):
            pattern[j] = chr(ord(pattern[j]) ^ i)
            if (ord(pattern[j]) not in values):
                notinvalues = True
                break

        # Skip search if the values of encoded string don't exist in data
        if (notinvalues):
            continue

        pos = buf.find("".join(pattern), 0)

        if (pos != -1):
            hits.append(pos)

        while (pos != -1):
            pos = buf.find("".join(pattern), pos + len(pattern))
            if (pos != -1):
                hits.append(pos)

        # Print search hits
        for j in hits:
            end = j + len(pattern) + LEN_AFTER_HIT
            if (end < length):
                hitstr = list(buf[j:end])
            else:
                hitstr = list(buf[j:])

            for k in range(0, len(hitstr)):
                c = ord(hitstr[k]) ^ i
                hitstr[k] = chr(c)

            hitstr = binascii.hexlify("".join(hitstr))
            hitstr = hitstr.upper()
            print "XOR key: 0x%02x offset: 0x%x search hit: %s" % (i, offset + j, hitstr)
            fi.setBookmark(offset + j, len(keyword), hex(offset + j), "#c8ffff")
            num_hits += 1

    return num_hits

def search_rol_hex(fi, buf, offset, length, keyword):
    """
    Search bit-rotated string
    Used by xor_hex_search()
    """
    LEN_AFTER_HIT = 30

    values = valdict(buf)
    num_hits = 0

    for i in range(1, 8):
        pattern = keyword[:]
        notinvalues = False
        hits = []

        # Encode search string and check whether the values of encoded string exist in data
        for j in range(0, len(pattern)):
            pattern[j] = chr(ror(ord(pattern[j]), i))
            if (ord(pattern[j]) not in values):
                notinvalues = True
                break

        # Skip search if the values of encoded string don't exist in data
        if (notinvalues):
            continue

        pos = buf.find("".join(pattern), 0)

        if (pos != -1):
            hits.append(pos)

        while (pos != -1):
            pos = buf.find("".join(pattern), pos + len(pattern))
            if (pos != -1):
                hits.append(pos)

        # Print search hits
        for j in hits:
            end = j + len(pattern) + LEN_AFTER_HIT
            if (end < length):
                hitstr = list(buf[j:end])
            else:
                hitstr = list(buf[j:])

            for k in range(0, len(hitstr)):
                c = rol(ord(hitstr[k]), i)
                hitstr[k] = chr(c)

            hitstr = binascii.hexlify("".join(hitstr))
            hitstr = hitstr.upper()
            print "ROL bit: %d offset: 0x%x search hit: %s" % (i, offset + j, hitstr)
            fi.setBookmark(offset + j, len(keyword), hex(offset + j), "#c8ffff")
            num_hits += 1

    return num_hits

def xor_hex_search(fi):
    """
    Search XORed / bit-rotated data in selected region (the whole file if not selected)
    """
    length_sel = fi.getSelectionLength()
    offset = fi.getSelectionOffset()
    keyword = fi.showSimpleDialog("Search keyword (in hex):")
    keyword = keyword.replace("0x", "")
    disp_keyword = "0x" + keyword.lower()
    keyword = list(binascii.unhexlify(keyword))

    if (len(keyword) > 0):
        if (length_sel > 0):
            length = length_sel
            buf = fi.getSelection()
            print "Search XORed / bit-rotated data from offset %s to %s with keyword %s" % (hex(offset), hex(offset + length - 1), disp_keyword)
        else:
            buf = fi.getDocument()
            length = fi.getLength()
            offset = 0
            print "Search XORed / bit-rotated data in the whole file with keyword %s" % disp_keyword

        num_xor = search_xor_hex(fi, buf, offset, length, keyword)
        num_rol = search_rol_hex(fi, buf, offset, length, keyword)
        if num_xor + num_rol == 1:
            print "Added a bookmark to the search hit."
        elif num_xor + num_rol > 1:
            print "Added bookmarks to the search hits."

def search_xor_text(fi, buf, offset, length, keyword):
    """
    Search XORed string
    Used by xor_text_search()
    """
    LEN_AFTER_HIT = 50

    values = valdict(buf)
    num_hits = 0

    for i in range(0, length):
        v = ord(buf[i])
        if (v not in values):
            values[v] = True

    for i in range(0, 256):
        pattern = keyword[:]
        notinvalues = False
        hits = []

        # Encode search string and check whether the values of encoded string exist in data
        for j in range(0, len(pattern)):
            pattern[j] = chr(ord(pattern[j]) ^ i)
            if (ord(pattern[j]) not in values):
                notinvalues = True
                break

        # Skip search if the values of encoded string don't exist in data
        if (notinvalues):
            continue

        pos = buf.find("".join(pattern), 0)

        if (pos != -1):
            hits.append(pos)

        while (pos != -1):
            pos = buf.find("".join(pattern), pos + len(pattern))
            if (pos != -1):
                hits.append(pos)

        # Print search hits
        for j in hits:
            end = j + len(pattern) + LEN_AFTER_HIT
            if (end < length):
                hitstr = list(buf[j:end])
            else:
                hitstr = list(buf[j:])

            for k in range(0, len(hitstr)):
                c = ord(hitstr[k]) ^ i
                if (c < 0x20 or c > 0x126):
                    c = 0x2e
                hitstr[k] = chr(c)

            print "XOR key: 0x%02x offset: 0x%x search hit: %s" % (i, offset + j, "".join(hitstr))
            fi.setBookmark(offset + j, len(keyword), hex(offset + j), "#c8ffff")
            num_hits += 1

    return num_hits

def search_rol_text(fi, buf, offset, length, keyword):
    """
    Search bit-rotated string
    Used by xor_text_search()
    """
    LEN_AFTER_HIT = 50

    values = valdict(buf)
    num_hits = 0

    for i in range(1, 8):
        pattern = keyword[:]
        notinvalues = False
        hits = []

        # Encode search string and check whether the values of encoded string exist in data
        for j in range(0, len(pattern)):
            pattern[j] = chr(ror(ord(pattern[j]), i))
            if (ord(pattern[j]) not in values):
                notinvalues = True
                break

        # Skip search if the values of encoded string don't exist in data
        if (notinvalues):
            continue

        pos = buf.find("".join(pattern), 0)

        if (pos != -1):
            hits.append(pos)

        while (pos != -1):
            pos = buf.find("".join(pattern), pos + len(pattern))
            if (pos != -1):
                hits.append(pos)

        # Print search hits
        for j in hits:
            end = j + len(pattern) + LEN_AFTER_HIT
            if (end < length):
                hitstr = list(buf[j:end])
            else:
                hitstr = list(buf[j:])

            for k in range(0, len(hitstr)):
                c = rol(ord(hitstr[k]), i)
                if (c < 0x20 or c > 0x126):
                    c = 0x2e
                hitstr[k] = chr(c)

            print "ROL bit: %d offset: 0x%x search hit: %s" % (i, offset + j, "".join(hitstr))
            fi.setBookmark(offset + j, len(keyword), hex(offset + j), "#c8ffff")
            num_hits += 1

    return num_hits

def xor_text_search(fi):
    """
    Search XORed / bit-rotated string in selected region (the whole file if not selected)
    """
    length_sel = fi.getSelectionLength()
    offset = fi.getSelectionOffset()
    keyword = list(fi.showSimpleDialog("Search keyword:"))

    if (len(keyword) > 0):
        if (length_sel > 0):
            length = length_sel
            buf = fi.getSelection()
            print "Search XORed / bit-rotated string from offset %s to %s with keyword '%s'" % (hex(offset), hex(offset + length - 1), "".join(keyword))
        else:
            buf = fi.getDocument()
            length = fi.getLength()
            offset = 0
            print "Search XORed / bit-rotated string in the whole file with keyword '%s'" % "".join(keyword)
        num_xor = search_xor_text(fi, buf, offset, length, keyword)
        num_rol = search_rol_text(fi, buf, offset, length, keyword)
        if num_xor + num_rol == 1:
            print "Added a bookmark to the search hit."
        elif num_xor + num_rol > 1:
            print "Added bookmarks to the search hits."

def regex_search(fi):
    """
    Search with regular expression in selected region (the whole file if not selected)
    """
    length_sel = fi.getSelectionLength()
    offset = fi.getSelectionOffset()
    keyword = fi.showSimpleDialog("Regular expression (please see https://docs.python.org/2.7/library/re.html for syntax):")

    if (len(keyword) > 0):
        if (length_sel > 0):
            length = length_sel
            buf = fi.getSelection()
            print "Search from offset %s to %s with keyword '%s'" % (hex(offset), hex(offset + length - 1), keyword)
        else:
            buf = fi.getDocument()
            length = fi.getLength()
            offset = 0
            print "Search in the whole file with keyword '%s'" % keyword

        try:
            re.compile(keyword)
        except:
            print "Error: invalid regular expression"
            return

        num_hits = 0
        match = re.finditer(keyword, buf)
        for m in match:
            print "Offset: 0x%x Search hit: %s" % (offset + m.start(), m.group())
            fi.setBookmark(offset + m.start(), m.end() - m.start(), hex(offset + m.start()), "#aaffaa")
            num_hits += 1

        if num_hits == 1:
            print "Added a bookmark to the search hit."
        elif num_hits > 1:
            print "Added bookmarks to the search hits."
