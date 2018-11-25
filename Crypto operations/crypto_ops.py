#
# Crypto operations - Various cryptographic operations
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

try:
    import Crypto.Cipher.ARC4
    pycrypto_not_installed = False
except ImportError:
    pycrypto_not_installed = True

def arc4_decrypt(fi):
    """
    Decrypt selected region with ARC4 (Alleged RC4) 
    """
    if pycrypto_not_installed:
        print "pycrypto is not installed."
        print "Please download the installer pycrypto-2.6.win32-py2.7.exe"
        print "from http://www.voidspace.org.uk/python/modules.shtml#pycrypto ,"
        print "install it and restart FileInsight."
        return

    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    if (length > 0):
        key = fi.showSimpleDialog("Decryption key (in hex):")
        key = key.replace("0x", "")
        key = binascii.a2b_hex(key)

        buf = fi.getSelection()
        newbuf = list(fi.getDocument())

        cipher = Crypto.Cipher.ARC4.new(key)
        decrypted_buf = list(cipher.decrypt(buf))

        for i in range(0, length):
            newbuf[offset + i] = decrypted_buf[i]

        fi.newDocument("New file", 1)
        fi.setDocument("".join(newbuf))
        fi.setBookmark(offset, length, hex(offset), "#c8ffff")

        if (length == 1):
            print "Decrypted one byte with ARC4 from offset %s to %s." % (hex(offset), hex(offset))
        else:
            print "Decrypted %s bytes with ARC4 from offset %s to %s." % (length, hex(offset), hex(offset + length - 1))
        print "Added a bookmark to decrypted region."
