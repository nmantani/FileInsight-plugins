#
# Bzip2 compress - Compress selected region with bzip2 algorithm
#
# Copyright (c) 2014, Nobutaka Mantani
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

import bz2

offset = getSelectionOffset()
length = getSelectionLength()

if (length > 0):
    data = getSelection()
    orig = list(getDocument())
    orig_len = len(orig)

    comp_buf = list(bz2.compress(data))
    final_size = len(comp_buf)
    newdata = [0] * (orig_len - (length - final_size))

    for i in range(0, offset):
        newdata[i] = orig[i]

    for i in range(0, final_size):
        newdata[offset + i] = comp_buf[i]

    for i in range(0, orig_len - offset - length):
        newdata[offset + final_size + i] = orig[offset + length + i]

    newDocument("New file", 1)
    setDocument("".join(newdata))
    setBookmark(offset, final_size, hex(offset), "#c8ffff")

    if (length == 1):
        print "Compressed one byte from offset %s to %s." % (hex(offset), hex(offset))
    else:
        print "Compressed %s bytes from offset %s to %s." % (length, hex(offset), hex(offset + length - 1))
    print "Added a bookmark to compressed region."

