#
# Fill - Fill selected region with specified hex pattern
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

offset = getSelectionOffset()
length = getSelectionLength()

if (length > 0):
    pat = showSimpleDialog("Pattern (in hex):")
    pat = pat.replace("0x", "")

    l = []
    for i in range(0, len(pat), 2):
        l.append(pat[i:i+2])
    patlen = len(pat) / 2

    buf = list(getDocument())
    for i in range(0, length):
        j = offset + i
        buf[j] = chr(int(l[i % patlen], 16))
    newDocument("New file", 1)
    setDocument("".join(buf))

    if (length == 1):
        print "Filled one byte from offset %s to %s with the hex pattern %s." % (hex(offset), hex(offset), hex(int(pat, 16)))
    else:
        print "Filled %s bytes from offset %s to %s with the hex pattern %s." % (length, hex(offset), hex(offset + length - 1), hex(int(pat, 16)))

