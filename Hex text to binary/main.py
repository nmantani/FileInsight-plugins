#
# Hex text to binary - Convert hex text of selected region into binary
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

offset = getSelectionOffset()
length = getSelectionLength()

hexchars = {"0" : True,
            "1" : True,
            "2" : True,
            "3" : True,
            "4" : True,
            "5" : True,
            "6" : True,
            "7" : True,
            "8" : True,
            "9" : True,
            "A" : True,
            "B" : True,
            "C" : True,
            "D" : True,
            "E" : True,
            "F" : True,
            "a" : True,
            "b" : True,
            "c" : True,
            "d" : True,
            "e" : True,
            "f" : True}

if (length > 1):
    buf = list(getDocument())
    newbuf = []
    i = 0
    while (i < length):
        j = offset + i
        if (i < length - 1 and hexchars.get(buf[j]) and hexchars.get(buf[j + 1])):
            newbuf.append(chr(int(buf[j] + buf[j + 1], 16)))
        i += 2
    newDocument("New file", 1)
    setDocument("".join(newbuf))

    print "Converted hex text from offset %s to %s (%s bytes) into binary." % (hex(offset), hex(offset + length - 1), length)

