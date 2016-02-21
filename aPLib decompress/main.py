#
# aPLib decompress - Decompress selected region with aPLib compression library
#
# Copyright (c) 2016, Nobutaka Mantani
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

import ctypes

offset = getSelectionOffset()
length = getSelectionLength()

if (length > 0):
    data = getSelection()
    orig = list(getDocument())
    orig_len = len(orig)

    try:
        aplib = ctypes.windll.LoadLibrary('aplib.dll')

        final_size = aplib.aPsafe_get_orig_size(ctypes.c_char_p(data))

        if (final_size == -1):
            final_size = length
            count = 0
            ret = -1

            while (ret == -1 and count < 16):
                final_size *= 2
                uncompressed = ctypes.create_string_buffer(final_size)
                ret = aplib.aP_depack_asm_safe(ctypes.c_char_p(data), length, uncompressed, final_size)
                count +=1

            final_size = ret
        else:
            uncompressed = ctypes.create_string_buffer(final_size)
            final_size = aplib.aPsafe_depack(ctypes.c_char_p(data), length, uncompressed, final_size)

        if (final_size == -1):
            raise Exception

        uncompressed = list(uncompressed)
        uncompressed = uncompressed[:final_size]

        newdata = orig[:offset]
        newdata.extend(uncompressed)
        newdata.extend(orig[offset + length:])

        newDocument("New file", 1)
        setDocument("".join(newdata))
        setBookmark(offset, final_size, hex(offset), "#c8ffff")

        if (length == 1):
            print "Decompressed one byte from offset %s to %s." % (hex(offset), hex(offset))
        else:
            print "Decompressed %s bytes from offset %s to %s." % (length, hex(offset), hex(offset + length - 1))
        print "Added a bookmark to decompressed region."

    except WindowsError:
        print 'Error: cannot load aplib.dll'

    except Exception:
        print 'Error: invalid compressed data'

