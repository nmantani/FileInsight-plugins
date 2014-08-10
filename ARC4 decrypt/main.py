#
# ARC4 decrypt - Decrypt selected region with ARC4 (Alleged RC4) 
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

import Crypto.Cipher.ARC4
import binascii

offset = getSelectionOffset()
length = getSelectionLength()

if (length > 0):
    key = showSimpleDialog("Decryption key (in hex):")
    key = key.replace("0x", "")
    key = binascii.a2b_hex(key)

    buf = getSelection()
    newbuf = list(getDocument())

    cipher = Crypto.Cipher.ARC4.new(key)
    decrypted_buf = list(cipher.decrypt(buf))

    for i in range(0, length):
        newbuf[offset + i] = decrypted_buf[i]

    newDocument("New file", 1)
    setDocument("".join(newbuf))
    setBookmark(offset, length, hex(offset), "#c8ffff")

    if (length == 1):
        print "Decrypted one byte with ARC4 from offset %s to %s." % (hex(offset), hex(offset))
    else:
        print "Decrypted %s bytes with ARC4 from offset %s to %s." % (length, hex(offset), hex(offset + length - 1))
    print "Added a bookmark to decrypted region."

