#
# Basic operations - Various editing operations
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

def copy_to_new_file(fi):
    """
    Copy selected region (the whole file if not selected) to new file
    """
    length = fi.getSelectionLength()
    if (length > 0):
        data = fi.getSelection()
    else:
        data = fi.getDocument()
    fi.newDocument("New file", 1)
    fi.setDocument(data)

def delete_before(fi):
    """
    Delete all region before current curor position
    """
    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    buf = list(fi.getDocument())
    buf = buf[offset:]

    fi.newDocument("New file", 1)
    fi.setDocument("".join(buf))

    if offset > 0:
        offset = offset - 1

    print "Deleted from the beginning of the file to offset %s." % hex(offset)

def delete_after(fi):
    """
    Delete all region after current cursor position
    """
    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    buf = list(fi.getDocument())
    buf = buf[:offset+1]

    fi.newDocument("New file", 1)
    fi.setDocument("".join(buf))

    print "Deleted from offset %s to the end of the file." % hex(offset+1)

def fill(fi):
    """
    Fill selected region with specified hex pattern
    """
    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    if (length > 0):
        pat = fi.showSimpleDialog("Pattern (in hex):")
        pat = pat.replace("0x", "")

        l = []
        for i in range(0, len(pat), 2):
            l.append(pat[i:i+2])
        patlen = len(pat) / 2

        buf = list(fi.getDocument())
        for i in range(0, length):
            j = offset + i
            buf[j] = chr(int(l[i % patlen], 16))
        fi.newDocument("New file", 1)
        fi.setDocument("".join(buf))
        fi.setBookmark(offset, length, hex(offset), "#c8ffff")

        if (length == 1):
            print "Filled one byte from offset %s to %s with the hex pattern %s." % (hex(offset), hex(offset), hex(int(pat, 16)))
        else:
            print "Filled %s bytes from offset %s to %s with the hex pattern %s." % (length, hex(offset), hex(offset + length - 1), hex(int(pat, 16)))
        print "Added a bookmark to filled region."

def invert(fi):
    """
    Invert bits of selected region
    """
    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    if (length > 0):
        buf = list(fi.getDocument())

        for i in range(0, length):
            j = offset + i
            buf[j] = chr(~ord(buf[j]) & 0xff)

        fi.newDocument("New file", 1)
        fi.setDocument("".join(buf))
        fi.setBookmark(offset, length, hex(offset), "#c8ffff")

        if (length == 1):
            print "Inverted one byte at offset %s." % hex(offset)
        else:
            print "Inverted %s bytes from offset %s to %s." % (length, hex(offset), hex(offset + length - 1))
        print "Added a bookmark to inverted region."

def reverse_order(fi):
    """
    Reverse order of selected region
    """
    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    if (length > 1):
        buf = list(fi.getDocument())
        i = 0
        end = length / 2
        while (i < end):
            j = offset + i
            k = offset + length - i - 1
            tmp = buf[j]
            buf[j] = buf[k]
            buf[k] = tmp
            i += 1
        fi.newDocument("New file", 1)
        fi.setDocument("".join(buf))
        fi.setBookmark(offset, length, hex(offset), "#c8ffff")

        print "Reversed order from offset %s to %s (%s bytes)." % (hex(offset), hex(offset + length - 1), length)
        print "Added a bookmark to reversed region."

def swap_nibbles(fi):
    """
    Swap each pair of nibbles of selected region
    """
    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    buf = list(fi.getDocument())
    i = 0
    while (i < length):
        j = offset + i
        buf[j] = chr(((ord(buf[j]) >> 4) & 0x0f ) | ((ord(buf[j]) << 4) & 0xf0))
        i += 1

    fi.newDocument("New file", 1)
    fi.setDocument("".join(buf))
    fi.setBookmark(offset, length, hex(offset), "#c8ffff")

    print "Swapped each pair of nibbles from offset %s to %s (%s bytes)." % (hex(offset), hex(offset + length - 1), length)
    print "Added a bookmark to swapped region."

def swap_two_bytes(fi):
    """
    Swap each pair of bytes of selected region
    """
    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    if (length > 1):
        buf = list(fi.getDocument())
        i = 0
        while (i < length):
            j = offset + i
            if (i < length - 1):
                tmp = buf[j]
                buf[j] = buf[j + 1]
                buf[j + 1] = tmp
            i += 2
        fi.newDocument("New file", 1)
        fi.setDocument("".join(buf))
        fi.setBookmark(offset, length, hex(offset), "#c8ffff")

        print "Swapped each pair of bytes from offset %s to %s (%s bytes)." % (hex(offset), hex(offset + length - 1), length)
        print "Added a bookmark to swapped region."
