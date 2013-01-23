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

length = getSelectionLength()
offset = getSelectionOffset()

if (length > 0):
    buf = getSelection()
    print "Top five 256 byte XOR key guessed from offset %s to %s" % (hex(offset), hex(offset + length - 1))
else:
    buf = getDocument()
    length = getLength()
    print "Top five 256 byte XOR key guessed from the whole file"

freq = {}
for i in range(0, 256):
    freq[i] = {}
    for j in range(0, 256):
        freq[i][j] = 0

for i in range(0, length):
    v = ord(buf[i])
    j = i % 256
    if (v in freq):
        freq[j][v] += 1

for i in range(0, 5):
    sys.stdout.write("0x")
    for j in range(255, -1, -1):
        l = sorted(freq[j].items(), key=lambda x:x[1], reverse=True)
        sys.stdout.write("%02X" % l[i][0])
    print

