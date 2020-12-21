#
# XOR operations - Various XOR related operations
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
import hashlib
import struct
import sys

def decremental_xor(fi):
    """
    XOR selected region while decrementing XOR key
    """
    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    if length > 0:
        key = fi.showSimpleDialog("XOR key (in hex, default = 0x00):")
        if key == "":
            key = 0
        else:
            try:
                key = int(key, 16)
            except:
                print("Error: XOR key is not hexadecimal.")
                return

        step = fi.showSimpleDialog("Decrement step (in hex, default = 0x01):")
        if step == "":
            step = 1
        else:
            try:
                step = int(step, 16)
            except:
                print("Error: decrement step is not hexadecimal.")
                return

        init_key = key
        buf = list(fi.getDocument())

        for i in range(0, length):
            j = offset + i
            buf[j] = chr(ord(buf[j]) ^ key)
            key -= step
            key = key & 0xff

        fi.newDocument("Output of Decremental XOR", 1)
        fi.setDocument("".join(buf))
        fi.setBookmark(offset, length, hex(offset), "#c8ffff")

        if length == 1:
            print("XORed one byte from offset %s to %s while decrementing key from %s (step %s)." % (hex(offset), hex(offset), hex(init_key), hex(step)))
        else:
            print("XORed %s bytes from offset %s to %s while decrementing key from %s (step %s)." % (length, hex(offset), hex(offset + length - 1), hex(init_key), hex(step)))
            print("Added a bookmark to XORed region.")

def incremental_xor(fi):
    """
    XOR selected region while incrementing XOR key
    """
    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    if length > 0:
        key = fi.showSimpleDialog("XOR key (in hex, default = 0x00):")
        if key == "":
            key = 0
        else:
            try:
                key = int(key, 16)
            except:
                print("Error: XOR key is not hexadecimal.")
                return

        step = fi.showSimpleDialog("Increment step (in hex, default = 0x01):")
        if step == "":
            step = 1
        else:
            try:
                step = int(step, 16)
            except:
                print("Error: increment step is not hexadecimal.")
                return

        init_key = key
        buf = list(fi.getDocument())

        for i in range(0, length):
            j = offset + i
            buf[j] = chr(ord(buf[j]) ^ key)
            key += step
            key = key & 0xff

        fi.newDocument("Output of Incremental XOR", 1)
        fi.setDocument("".join(buf))
        fi.setBookmark(offset, length, hex(offset), "#c8ffff")

        if length == 1:
            print("XORed one byte from offset %s to %s while incrementing key from %s (step %s)." % (hex(offset), hex(offset), hex(init_key), hex(step)))
        else:
            print("XORed %s bytes from offset %s to %s while incrementing key from %s (step %s)." % (length, hex(offset), hex(offset + length - 1), hex(init_key), hex(step)))
            print("Added a bookmark to XORed region.")

def null_preserving_xor(fi):
    """
    XOR selected region while skipping null bytes
    """
    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    if length > 0:
        key = fi.showSimpleDialog("XOR key (in hex):")
        try:
            key = int(key, 16)
        except:
            print("Error: XOR key is not hexadecimal.")
            return

        buf = list(fi.getDocument())
        for i in range(0, length):
            j = offset + i
            if ord(buf[j]) != 0x00 and ord(buf[j]) != key:
                buf[j] = chr(ord(buf[j]) ^ key)
        fi.newDocument("Output of Null-preserving XOR", 1)
        fi.setDocument("".join(buf))
        fi.setBookmark(offset, length, hex(offset), "#c8ffff")

        if length == 1:
            print("XORed one byte from offset %s to %s with key %s while skipping data 0x00 and %s." % (hex(offset), hex(offset), hex(key), hex(key)))
        else:
            print("XORed %s bytes from offset %s to %s with key %s while skipping data 0x00 and %s." % (length, hex(offset), hex(offset + length - 1), hex(key), hex(key)))
        print("Added a bookmark to XORed region.")

def xor_with_next_byte(fi):
    """
    XOR selected region while using next byte as XOR key
    """
    offset = fi.getSelectionOffset()
    length_sel = fi.getSelectionLength()
    length_all = fi.getLength()

    if length_sel > 0:
        buf = list(fi.getDocument())
        for i in range(0, length_sel):
            j = offset + i
            if ord(buf[j]) != 0x00 and j < length_all - 1:
                buf[j] = chr(ord(buf[j]) ^ ord(buf[j + 1]))
        fi.newDocument("Output of XOR with next byte", 1)
        fi.setDocument("".join(buf))
        fi.setBookmark(offset, length_sel, hex(offset), "#c8ffff")

        if length_sel == 1:
            print("XORed one byte from offset %s to %s while using next byte as XOR key." % (hex(offset), hex(offset)))
        else:
            print("XORed %s bytes from offset %s to %s while using next byte as XOR key." % (length_sel, hex(offset), hex(offset + length_sel - 1)))
            print("Added a bookmark to XORed region.")

def xor_with_multibyte_key(buf, key):
    """
    Used by guess_multibyte_xor_keys()
    """
    b = list(buf)
    k = list(key)
    length = len(buf)
    for i in range(0, length):
        b[i] = chr(ord(b[i]) ^ ord(k[i % 256]))
    return  "".join(b)

def find_ole_header(fi, buf, offset):
    """
    Used by guess_multibyte_xor_keys()
    """
    i = 0
    pos = 0
    found = 0
    length = len(buf)
    while i < length:
        pos = buf.find("".join(['\xd0', '\xcf', '\x11', '\xe0', '\xa1', '\xb1', '\x1a', '\xe1']), i)
        if pos == -1:
            break
        else:
            print("OLE2 Compound Document header found at offset %s." % hex(offset + pos))
            fi.setBookmark(offset + pos, 8, hex(offset + pos), "#c8ffff")
            i = pos + 8
            found += 1
    return found

def find_pdf_header(fi, buf, offset):
    """
    Used by guess_multibyte_xor_keys()
    """
    i = 0
    pos = 0
    found = 0
    length = len(buf)
    while i < length:
        pos = buf.find("%PDF", i)
        if pos == -1:
            break
        else:
            print("PDF header found at offset %s." % hex(offset + pos))
            fi.setBookmark(offset + pos, 4, hex(offset + pos), "#c8ffff")
            i = pos + 4
            found += 1
    return found

def find_pe_header(fi, buf, offset):
    """
    Used by guess_multibyte_xor_keys()
    """
    i = 0
    pos = 0
    found = 0
    length = len(buf)
    while i < length:
        pos = buf.find("MZ", i)
        if pos == -1:
            break
        else:
            if pos + 64 < length:
                # Get the offset of the "PE" characters
                pe_offset = struct.unpack("<I", buf[pos+60:pos+64])[0]
                if pos + pe_offset + 23 < length:
                    # Check machine
                    if buf[pos+pe_offset:pos+pe_offset+6] == "".join(['P', 'E', '\x00', '\x00', '\x4c', '\x01']):
                        # Check characteristics
                        if struct.unpack("B", buf[pos+pe_offset+23])[0] & 0x20:
                            print("Win32 DLL found at offset %s." % hex(offset + pos))
                        else:
                            print("Win32 executable found at offset %s." % hex(offset + pos))
                        fi.setBookmark(offset + pos, 2, hex(offset + pos), "#c8ffff")
                        found += 1
                    elif buf[pos+pe_offset:pos+pe_offset+6] == "".join(['P', 'E', '\x00', '\x00', '\x64', '\x86']):
                        # Check characteristics
                        if struct.unpack("B", buf[pos+pe_offset+23])[0] & 0x20:
                            print("Win64 DLL found at offset %s." % hex(offset + pos))
                        else:
                            print("Win64 executable found at offset %s." % hex(offset + pos))
                        fi.setBookmark(offset + pos, 2, hex(offset + pos), "#c8ffff")
                        found += 1
            i = pos + 2
    return found

def find_elf_header(fi, buf, offset):
    """
    Used by guess_multibyte_xor_keys()
    """
    i = 0
    pos = 0
    found = 0
    length = len(buf)
    machine_dict = {0x02: "sparc", 0x03: "x86", 0x08: "mips", 0x14: "powerpc", 0x28: "arm", 0x2A: "superh", 0x32: "ia_64",
                    0x3E: "x86_64", 0xB7: "aarch64", 0xF3: "riscv", 0xF7: "bpf"}

    while i < length:
        pos = buf.find("\x7fELF", i)
        if pos == -1:
            break
        else:
            bits = 0
            if buf[pos + 4] == "\x01":
                bits = 32
            elif buf[pos + 4] == "\x02":
                bits = 64

            endian = ""
            if buf[pos + 5] == "\x01":
                endian = "little"
            elif buf[pos + 5] == "\x02":
                endian = "big"

            machine = ""
            if endian == "little":
                if ord(buf[pos + 0x12]) in machine_dict.keys():
                    machine = machine_dict[ord(buf[pos + 0x12])]
            elif endian == "big":
                if ord(buf[pos + 0x13]) in machine_dict.keys():
                    machine = machine_dict[ord(buf[pos + 0x13])]

            if bits != 0 and endian != "" and machine != "":
                print("ELF%d (%s %s endian) file found at offset %s." % (bits, machine, endian, hex(offset + pos)))
                fi.setBookmark(offset + pos, 4, hex(offset + pos), "#c8ffff")
                found += 1

            i = pos + 4
    return found

def find_rtf_header(fi, buf, offset):
    """
    Used by guess_multibyte_xor_keys()
    """
    i = 0
    pos = 0
    found = 0
    length = len(buf)
    while i < length:
        pos = buf.find("{\\rtf", i)
        if pos == -1:
            break
        else:
            print("RTF header found at offset %s." % hex(offset + pos))
            fi.setBookmark(offset + pos, 5, hex(offset + pos), "#c8ffff")
            i = pos + 5
            found += 1
    return found

def shorten_xor_key(key):
    """
    Return shortened XOR key if the key has a cyclic pattern
    Used by guess_multibyte_xor_keys()
    """
    key_len = [1, 2, 4, 8, 16, 32, 64, 128]

    for i in range(0, len(key_len)):
        cyclic = True
        for j in range(key_len[i], 256, key_len[i]):
            if key[0:key_len[i]] != key[j:j+key_len[i]]:
                cyclic = False
                break

        if cyclic:
            return key[0:key_len[i]]

    return key

def guess_multibyte_xor_keys(fi):
    """
    Guess multibyte XOR keys from selected region (the whole file if not selected) based on revealed keys that are XORed with 0x00
    """
    length = fi.getSelectionLength()
    offset = fi.getSelectionOffset()

    if length > 0:
        buf = fi.getSelection()
        print("Top ten XOR keys guessed from offset %s to %s" % (hex(offset), hex(offset + length - 1)))
        print("Please select the whole file and use these XOR key in the Decode tab to decode the file.\n")
    else:
        offset = 0
        buf = fi.getDocument()
        length = fi.getLength()
        print("Top ten XOR keys guessed from the whole file")
        print("Please select the whole file and use these XOR keys in the Decode tab to decode the file.\n")

    block = {}
    freq = {}
    for i in range(0, length, 256):
        # Do not use the first 256 byte as XOR key because it may contain a file header
        if i == 0 and offset == 0:
            continue

        b = buf[i:i + 256]
        if len(b) == 256:
            h = hashlib.md5(b).hexdigest()
            if h not in block:
                block[h] = b
                freq[h] = 1
            else:
                freq[h] += 1

    i = 0
    for k, v in sorted(freq.items(), key=lambda x:x[1], reverse=True):
        if i < 10:
            key = shorten_xor_key(block[k])
            sys.stdout.write("XOR key: 0x")
            for j in range(len(key) - 1, -1, -1):
                sys.stdout.write("%02x" % ord(block[k][j]))
            print
            print("256 bytes pattern occurrence count: %i" % v)
            tmp = xor_with_multibyte_key(buf, block[k])
            num_pe = find_pe_header(fi, tmp, offset)
            num_elf = find_elf_header(fi, tmp, offset)
            num_ole = find_ole_header(fi, tmp, offset)
            num_pdf = find_pdf_header(fi, tmp, offset)
            num_rtf = find_rtf_header(fi, tmp, offset)
            if num_pe + num_elf + num_ole + num_pdf + num_rtf == 1:
                print("Added a bookmark to the search hit.")
            elif num_pe + num_elf + num_ole + num_pdf + num_rtf > 1:
                print("Added bookmarks to the search hits.")
            print("")
            i += 1

def visual_decrypt(fi):
    """
    Decode selected region with visual decrypt algorithm
    """
    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    if length > 0:
        buf = list(fi.getDocument())
        for i in range(offset + length - 1, offset, -1):
            buf[i] = chr(ord(buf[i]) ^ ord(buf[i - 1]))
        fi.newDocument("Output of Visual Decrypt", 1)
        fi.setDocument("".join(buf))
        fi.setBookmark(offset, length, hex(offset), "#c8ffff")

        if length == 1:
            print("Decoded one byte from offset %s to %s." % (hex(offset), hex(offset)))
        else:
            print("Decoded %s bytes from offset %s to %s." % (length, hex(offset), hex(offset + length - 1)))
        print("Added a bookmark to decoded region.")

def visual_encrypt(fi):
    """
    Encode selected region with visual encrypt algorithm
    """
    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    if length > 0:
        buf = list(fi.getDocument())
        for i in range(offset + 1, offset + length):
            buf[i] = chr(ord(buf[i]) ^ ord(buf[i - 1]))
        fi.newDocument("Output of Visual Encrypt", 1)
        fi.setDocument("".join(buf))
        fi.setBookmark(offset, length, hex(offset), "#c8ffff")

        if length == 1:
            print("Encoded one byte from offset %s to %s." % (hex(offset), hex(offset)))
        else:
            print("Encoded %s bytes from offset %s to %s." % (length, hex(offset), hex(offset + length - 1)))
        print("Added a bookmark to encoded region.")

