#
# XOR with next byte - XOR selected region while using next byte as XOR key
#
# Copyright (c) 2012, 2013, Nobutaka Mantani
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

offset = getSelectionOffset()
length_sel = getSelectionLength()
length_all = getLength()

if (length_sel > 0):
    buf = list(getDocument())
    for i in range(0, length_sel):
        j = offset + i
        if (ord(buf[j]) != 0x00 and j < length_all - 1):
            buf[j] = chr(ord(buf[j]) ^ ord(buf[j + 1]))
    newDocument("New file", 1)
    setDocument("".join(buf))
    setBookmark(offset, length_sel, hex(offset), "#c8ffff")

    if (length_sel == 1):
        print "XORed one byte from offset %s to %s while using next byte as XOR key." % (hex(offset), hex(offset))
    else:
        print "XORed %s bytes from offset %s to %s while using next byte as XOR key." % (length_sel, hex(offset), hex(offset + length_sel - 1))
    print "Added a bookmark to XORed region."

