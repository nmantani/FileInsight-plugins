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

import binascii
import subprocess

def copy_to_new_file(fi):
    """
    Copy selected region (the whole file if not selected) to new file
    """
    length = fi.getSelectionLength()
    if length > 0:
        data = fi.getSelection()
    else:
        data = fi.getDocument()
    fi.newDocument("New file", 1)
    fi.setDocument(data)

def cut_binary_to_clipboard(fi):
    """
    Cut binary data of selected region to clipboard as hex-encoded text
    """
    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()
    if length > 0:
        cut = fi.getSelection()
        if cut == None: # For the case that getSelection() fails
            return
        binstr = binascii.b2a_hex(cut).upper()
        binstr = " ".join([binstr[i:i+2] for i in range(0, len(binstr), 2)])

        # Do not show command prompt window
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        # Execute copy_to_clipboard.py
        p = subprocess.Popen(["py.exe", "-3", "copy_to_clipboard.py"], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE)

        # Receive result
        stdout_data, stderr_data = p.communicate(binstr)
        ret = p.wait()

        data = list(fi.getDocument())
        before = "".join(data[:offset])
        after = "".join(data[offset+length:])

        fi.setDocument(before + after)

        if length == 1:
            print("One byte has been cut and copied to clipboard at offset %s." % hex(offset))
        else:
            print("%s bytes have been cut and copied to clipboard at offset %s." % (length, hex(offset)))

def copy_binary_to_clipboard(fi):
    """
    Copy binary data to clipboard as hex-encoded text
    """
    length = fi.getSelectionLength()
    if length > 0:
        data = fi.getSelection()
        if data == None: # For the case that getSelection() fails
            return
        binstr = binascii.b2a_hex(data).upper()
        binstr = " ".join([binstr[i:i+2] for i in range(0, len(binstr), 2)])

        # Do not show command prompt window
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        # Execute copy_to_clipboard.py
        p = subprocess.Popen(["py.exe", "-3", "copy_to_clipboard.py"], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE)

        # Receive result
        stdout_data, stderr_data = p.communicate(binstr)
        ret = p.wait()

        if length == 1:
            print("One byte has been copied to clipboard.")
        else:
            print("%s bytes have been copied to clipboard." % length)

def paste_binary_from_clipboard(fi):
    """
    Paste binary data (converted from hex-encoded text) from clipboard
    """

    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    data = list(fi.getDocument())
    before = "".join(data[:offset])
    after = "".join(data[offset+length:])

    # Do not show command prompt window
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

    # Execute paste_from_clipboard.py
    p = subprocess.Popen(["py.exe", "-3", "paste_from_clipboard.py"], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE)

    # Receive result
    stdout_data, stderr_data = p.communicate()
    ret = p.wait()

    inserted = binascii.a2b_hex("".join(stdout_data.split()))
    fi.setDocument(before + inserted + after)
    fi.setBookmark(offset, len(inserted), hex(offset), "#c8ffff")

    if len(inserted) == 1:
        print("One byte has been pasted from clipboard at offset %s." % hex(offset))
    else:
        print("%s bytes have been pasted from clipboard at offset %s." % (len(inserted), hex(offset)))

    print("Added a bookmark to pasted region.")

def delete_before(fi):
    """
    Delete all region before current curor position
    """
    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    data = list(fi.getDocument())
    data = data[offset:]

    fi.newDocument("New file", 1)
    fi.setDocument("".join(data))

    if offset > 0:
        offset = offset - 1

    print("Deleted from the beginning of the file to offset %s." % hex(offset))

def delete_after(fi):
    """
    Delete all region after current cursor position
    """
    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    data = list(fi.getDocument())
    data = data[:offset+1]

    fi.newDocument("New file", 1)
    fi.setDocument("".join(data))

    print("Deleted from offset %s to the end of the file." % hex(offset+1))

def fill(fi):
    """
    Fill selected region with specified hex pattern
    """
    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    if length > 0:
        pat = fi.showSimpleDialog("Pattern (in hex):")
        pat = pat.replace("0x", "")

        l = []
        for i in range(0, len(pat), 2):
            l.append(pat[i:i+2])
        patlen = len(pat) / 2

        data = list(fi.getDocument())
        for i in range(0, length):
            j = offset + i
            data[j] = chr(int(l[i % patlen], 16))
        fi.newDocument("New file", 1)
        fi.setDocument("".join(data))
        fi.setBookmark(offset, length, hex(offset), "#c8ffff")

        if length == 1:
            print("Filled one byte from offset %s to %s with the hex pattern %s." % (hex(offset), hex(offset), hex(int(pat, 16))))
        else:
            print("Filled %s bytes from offset %s to %s with the hex pattern %s." % (length, hex(offset), hex(offset + length - 1), hex(int(pat, 16))))
        print("Added a bookmark to filled region.")

def invert(fi):
    """
    Invert bits of selected region
    """
    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    if length > 0:
        data = list(fi.getDocument())

        for i in range(0, length):
            j = offset + i
            data[j] = chr(~ord(data[j]) & 0xff)

        fi.newDocument("New file", 1)
        fi.setDocument("".join(data))
        fi.setBookmark(offset, length, hex(offset), "#c8ffff")

        if length == 1:
            print("Inverted one byte at offset %s." % hex(offset))
        else:
            print("Inverted %s bytes from offset %s to %s." % (length, hex(offset), hex(offset + length - 1)))
        print("Added a bookmark to inverted region.")

def reverse_order(fi):
    """
    Reverse order of selected region
    """
    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    if (length > 1):
        data = list(fi.getDocument())
        i = 0
        end = length / 2
        while (i < end):
            j = offset + i
            k = offset + length - i - 1
            tmp = data[j]
            data[j] = data[k]
            data[k] = tmp
            i += 1
        fi.newDocument("New file", 1)
        fi.setDocument("".join(data))
        fi.setBookmark(offset, length, hex(offset), "#c8ffff")

        print("Reversed order from offset %s to %s (%s bytes)." % (hex(offset), hex(offset + length - 1), length))
        print("Added a bookmark to reversed region.")

def swap_nibbles(fi):
    """
    Swap each pair of nibbles of selected region
    """
    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    data = list(fi.getDocument())
    i = 0
    while (i < length):
        j = offset + i
        data[j] = chr(((ord(data[j]) >> 4) & 0x0f ) | ((ord(data[j]) << 4) & 0xf0))
        i += 1

    fi.newDocument("New file", 1)
    fi.setDocument("".join(data))
    fi.setBookmark(offset, length, hex(offset), "#c8ffff")

    print("Swapped each pair of nibbles from offset %s to %s (%s bytes)." % (hex(offset), hex(offset + length - 1), length))
    print("Added a bookmark to swapped region.")

def swap_two_bytes(fi):
    """
    Swap each pair of bytes of selected region
    """
    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    if (length > 1):
        data = list(fi.getDocument())
        i = 0
        while (i < length):
            j = offset + i
            if (i < length - 1):
                tmp = data[j]
                data[j] = data[j + 1]
                data[j + 1] = tmp
            i += 2
        fi.newDocument("New file", 1)
        fi.setDocument("".join(data))
        fi.setBookmark(offset, length, hex(offset), "#c8ffff")

        print("Swapped each pair of bytes from offset %s to %s (%s bytes)." % (hex(offset), hex(offset + length - 1), length))
        print("Added a bookmark to swapped region.")

def to_upper_case(fi):
    """
    Convert text to upper case of selected region
    """
    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()
    if length > 0:
        data = list(fi.getDocument())

        for i in range(0, length):
            j = offset + i
            if ord(data[j]) >= 0x61 and ord(data[j]) <= 0x7A:
                data[j] = chr(ord(data[j]) ^ 0x20)

        fi.newDocument("New file", 1)
        fi.setDocument("".join(data))
        fi.setBookmark(offset, length, hex(offset), "#c8ffff")

        if length == 1:
            print("Converted one byte at offset %s." % hex(offset))
        else:
            print("Converted %s bytes from offset %s to %s." % (length, hex(offset), hex(offset + length - 1)))
        print("Added a bookmark to converted region.")

def to_lower_case(fi):
    """
    Convert text to lower case of selected region
    """
    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()
    if length > 0:
        data = list(fi.getDocument())

        for i in range(0, length):
            j = offset + i
            if ord(data[j]) >= 0x41 and ord(data[j]) <= 0x5A:
                data[j] = chr(ord(data[j]) ^ 0x20)

        fi.newDocument("New file", 1)
        fi.setDocument("".join(data))
        fi.setBookmark(offset, length, hex(offset), "#c8ffff")

        if length == 1:
            print("Converted one byte at offset %s." % hex(offset))
        else:
            print("Converted %s bytes from offset %s to %s." % (length, hex(offset), hex(offset + length - 1)))
        print("Added a bookmark to converted region.")

def swap_case(fi):
    """
    Swap case of selected region
    """
    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()
    if length > 0:
        data = list(fi.getDocument())

        for i in range(0, length):
            j = offset + i
            if (ord(data[j]) >= 0x41 and ord(data[j]) <= 0x5A) or (ord(data[j]) >= 0x61 and ord(data[j]) <= 0x7A):
                data[j] = chr(ord(data[j]) ^ 0x20)

        fi.newDocument("New file", 1)
        fi.setDocument("".join(data))
        fi.setBookmark(offset, length, hex(offset), "#c8ffff")

        if length == 1:
            print("Converted one byte at offset %s." % hex(offset))
        else:
            print("Converted %s bytes from offset %s to %s." % (length, hex(offset), hex(offset + length - 1)))
        print("Added a bookmark to converted region.")

