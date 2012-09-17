#
# XOR search - Search XORed / bit-rotated string in selected region (the whole
# file if not selected)
#
# Copyright (c) 2012, Nobutaka Mantani
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

LEN_AFTER_HIT = 50

# Make bad-character shift table for quick search
def make_table(pattern, size):
    table = [size + 1] * 256
    for i in xrange(size):
        table[ord(pattern[i])] = size - i

    return table

# Sunday's Quick Search
def quick_search(buf, pattern, start):
    buf_end = len(buf) - 1
    len_pat = len(pattern)
    table = make_table(pattern, len_pat)
    i = start
    while i <= buf_end - len_pat:
        j = 0
        while j < len_pat:
            if (buf[i + j] != pattern[j]):
                break
            j += 1
        if (j == len_pat):
            return i
        else:
            i += table[ord(buf[i + len_pat])]

    return None

# Masking bits
def mask(x):
   if (x >= 0):
       return 2 ** x - 1
   else:
       return 0

# Bitwise rotate right
def ror(x, rot=1):
    rot %= 8
    if (rot < 1):
        return x
    x &= mask(8)
    return (x >> rot) | ((x << (8 - rot)) & mask(8))

# Bitwise rotate left
def rol(x, rot=1):
    rot %= 8
    if (rot < 1):
        return x
    x &= mask(8)
    return ((x << rot) & mask(8)) | (x >> (8 - rot))

# Make dictionary of values in data
def valdict(buf):
    values = {}

    for i in range(0, length):
        v = ord(buf[i])
        if (v not in values):
            values[v] = True

    return values

# Search XORed string
def search_xor(buf, offset, length, keyword):
    values = valdict(buf)

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

        pos = quick_search(buf, pattern, 0)

        if (pos is not None):
            hits.append(pos)

        while (pos is not None):
            pos = quick_search(buf, pattern, pos + len(pattern))
            if (pos is not None):
                hits.append(pos)

        # Print search hits
        for j in hits:
            end = j + len(pattern) + LEN_AFTER_HIT
            if (end < length):
                hitstr = buf[j:end]
            else:
                hitstr = buf[j:]

            for k in range(0, len(hitstr)):
                c = ord(hitstr[k]) ^ i
                if (c < 0x20 or c > 0x126):
                    c = 0x2e
                hitstr[k] = chr(c)

            print "XOR key: 0x%02x offset: 0x%x search hit: %s" % (i, offset + j, "".join(hitstr))

# Search bit-rotated string
def search_rol(buf, offset, length, keyword):
    values = valdict(buf)

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

        pos = quick_search(buf, pattern, 0)

        if (pos is not None):
            hits.append(pos)

        while (pos is not None):
            pos = quick_search(buf, pattern, pos + len(pattern))
            if (pos is not None):
                hits.append(pos)

        # Print search hits
        for j in hits:
            end = j + len(pattern) + LEN_AFTER_HIT
            if (end < length):
                hitstr = buf[j:end]
            else:
                hitstr = buf[j:]

            for k in range(0, len(hitstr)):
                c = rol(ord(hitstr[k]), i)
                if (c < 0x20 or c > 0x126):
                    c = 0x2e
                hitstr[k] = chr(c)

            print "ROL bit: %d offset: 0x%x search hit: %s" % (i, offset + j, "".join(hitstr))

length_sel = getSelectionLength()
offset = getSelectionOffset()
keyword = list(showSimpleDialog("Search keyword:"))

if (len(keyword) > 0):
    if (length_sel > 0):
        length = length_sel
        buf = list(getSelection())
        print "Search XORed / bit-rotated string from offset %s to %s with keyword '%s'" % (hex(offset), hex(offset + length - 1), "".join(keyword))
    else:
        buf = list(getDocument())
        length = getLength()
        offset = 0
        print "Search XORed / bit-rotated string in the whole file with keyword '%s'" % "".join(keyword)

    search_xor(buf, offset, length, keyword)
    search_rol(buf, offset, length, keyword)

