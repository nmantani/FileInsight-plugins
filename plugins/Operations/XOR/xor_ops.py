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
import subprocess
import sys
import time

def decremental_xor(fi):
    """
    XOR selected region while decrementing XOR key
    """
    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    if length > 0:
        key = fi.showSimpleDialog("XOR key (in hex, default = 0x00):")

        # Dialog has been closed
        if key == None:
            return

        if key == "":
            key = 0
        else:
            try:
                key = int(key, 16)
            except:
                print("Error: XOR key is not hexadecimal.")
                return

        step = fi.showSimpleDialog("Decrement step (in hex, default = 0x01):")

        # Dialog has been closed
        if step == None:
            return

        if step == "":
            step = 1
        else:
            try:
                step = int(step, 16)
            except:
                print("Error: decrement step is not hexadecimal.")
                return

        init_key = key
        data = list(fi.getDocument())

        for i in range(0, length):
            j = offset + i
            data[j] = chr(ord(data[j]) ^ key)
            key -= step
            key = key & 0xff

        tab_name = fi.get_new_document_name("Output of Decremental XOR")
        fi.newDocument(tab_name, 1)
        fi.setDocument("".join(data))
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

        # Dialog has been closed
        if key == None:
            return

        if key == "":
            key = 0
        else:
            try:
                key = int(key, 16)
            except:
                print("Error: XOR key is not hexadecimal.")
                return

        step = fi.showSimpleDialog("Increment step (in hex, default = 0x01):")

        # Dialog has been closed
        if step == None:
            return

        if step == "":
            step = 1
        else:
            try:
                step = int(step, 16)
            except:
                print("Error: increment step is not hexadecimal.")
                return

        init_key = key
        data = list(fi.getDocument())

        for i in range(0, length):
            j = offset + i
            data[j] = chr(ord(data[j]) ^ key)
            key += step
            key = key & 0xff

        tab_name = fi.get_new_document_name("Output of Incremental XOR")
        fi.newDocument(tab_name, 1)
        fi.setDocument("".join(data))
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

        # Dialog has been closed
        if key == None:
            return

        try:
            key = int(key, 16)
        except:
            print("Error: XOR key is not hexadecimal.")
            return

        data = list(fi.getDocument())
        for i in range(0, length):
            j = offset + i
            if ord(data[j]) != 0x00 and ord(data[j]) != key:
                data[j] = chr(ord(data[j]) ^ key)

        tab_name = fi.get_new_document_name("Output of Null-preserving XOR")
        fi.newDocument(tab_name, 1)
        fi.setDocument("".join(data))
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
        data = list(fi.getDocument())
        for i in range(0, length_sel):
            j = offset + i
            if j < length_all - 1:
                data[j] = chr(ord(data[j]) ^ ord(data[j + 1]))

        tab_name = fi.get_new_document_name("Output of XOR with next byte")
        fi.newDocument(tab_name, 1)
        fi.setDocument("".join(data))
        fi.setBookmark(offset, length_sel, hex(offset), "#c8ffff")

        if length_sel == 1:
            print("XORed one byte from offset %s to %s while using next byte as XOR key." % (hex(offset), hex(offset)))
        else:
            print("XORed %s bytes from offset %s to %s while using next byte as XOR key." % (length_sel, hex(offset), hex(offset + length_sel - 1)))
            print("Added a bookmark to XORed region.")

def xor_with_next_byte_reverse(fi):
    """
    Reverse operation of "XOR with next byte" plugin
    """
    offset = fi.getSelectionOffset()
    length_sel = fi.getSelectionLength()
    length_all = fi.getLength()

    if length_sel > 0:
        data = list(fi.getDocument())
        for i in range(length_sel - 1, -1, -1):
            j = offset + i
            if j < length_all - 1:
                data[j] = chr(ord(data[j]) ^ ord(data[j + 1]))

        tab_name = fi.get_new_document_name("Output of XOR with next byte (reverse)")
        fi.newDocument(tab_name, 1)
        fi.setDocument("".join(data))
        fi.setBookmark(offset, length_sel, hex(offset), "#c8ffff")

        if length_sel == 1:
            print("XORed one byte from offset %s to %s while using next byte as XOR key (reverse direction)." % (hex(offset), hex(offset)))
        else:
            print("XORed %s bytes from offset %s to %s while using next byte as XOR key (reverse direction)." % (length_sel, hex(offset), hex(offset + length_sel - 1)))
            print("Added a bookmark to XORed region.")

def xor_with_multibyte_key(data, key):
    """
    Used by guess_multibyte_xor_keys()
    """
    d = list(data)
    k = list(key)
    length = len(data)
    for i in range(0, length):
        d[i] = chr(ord(d[i]) ^ ord(k[i % 256]))
    return  "".join(d)

def find_ole_header(fi, data, offset, output):
    """
    Used by guess_multibyte_xor_keys()
    """
    i = 0
    pos = 0
    found = 0
    length = len(data)
    while i < length:
        pos = data.find("".join(['\xd0', '\xcf', '\x11', '\xe0', '\xa1', '\xb1', '\x1a', '\xe1']), i)
        if pos == -1:
            break
        else:
            output += "OLE2 Compound Document header found at offset %s.\n" % hex(offset + pos)
            fi.setBookmark(offset + pos, 8, hex(offset + pos) + " OLE2 Compound Document", "#c8ffff")
            i = pos + 8
            found += 1
    return (found, output)

def find_pdf_header(fi, data, offset, output):
    """
    Used by guess_multibyte_xor_keys()
    """
    i = 0
    pos = 0
    found = 0
    length = len(data)
    while i < length:
        pos = data.find("%PDF", i)
        if pos == -1:
            break
        else:
            output += "PDF header found at offset %s.\n" % hex(offset + pos)
            fi.setBookmark(offset + pos, 4, hex(offset + pos) + " PDF", "#c8ffff")
            i = pos + 4
            found += 1
    return (found, output)

def find_pe_header(fi, data, offset, output):
    """
    Used by guess_multibyte_xor_keys()
    """
    # Do not show command prompt window
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

    # Execute find_pe_file.py for finding PE files
    p = subprocess.Popen(["py.exe", "-3", "Parsing/find_pe_file.py", str(offset)], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE)

    # Receive scan result
    stdout_data, stderr_data = p.communicate(data)
    ret = p.wait()

    if ret == -1:
        print("pefile is not installed.")
        print("Please install it with 'py.exe -3 -m pip install pefile' and try again.")
        return (-1, output)

    found = ret
    if found > 0:
        output += stdout_data

        for l in stdout_data.splitlines():
            if l[0:5] == "Win32" or l[0:5] == "Win64":
                file_type = l.split()[0] + " " + l.split()[1]
                off = int(l.split()[5], 0)
                size = int(l.split()[7], 0)
                if off + size > len(data):
                    fi.setBookmark(off, len(data) - off, hex(off) + " " + file_type, "#c8ffff")
                else:
                    fi.setBookmark(off, size, hex(off) + " " + file_type, "#c8ffff")

    return (found, output)

def find_elf_header(fi, data, offset, output):
    """
    Used by guess_multibyte_xor_keys()
    """
    i = 0
    pos = 0
    found = 0
    length = len(data)
    machine_dict = {0x02: "sparc", 0x03: "x86", 0x08: "mips", 0x14: "powerpc", 0x28: "arm", 0x2A: "superh", 0x32: "ia_64",
                    0x3E: "x86_64", 0xB7: "aarch64", 0xF3: "riscv", 0xF7: "bpf"}

    while i < length:
        pos = data.find("\x7fELF", i)
        if pos == -1:
            break
        else:
            bits = 0
            if data[pos + 4] == "\x01":
                bits = 32
            elif data[pos + 4] == "\x02":
                bits = 64

            endian = ""
            if data[pos + 5] == "\x01":
                endian = "little"
            elif data[pos + 5] == "\x02":
                endian = "big"

            machine = ""
            if endian == "little":
                if ord(data[pos + 0x12]) in machine_dict.keys():
                    machine = machine_dict[ord(data[pos + 0x12])]
            elif endian == "big":
                if ord(data[pos + 0x13]) in machine_dict.keys():
                    machine = machine_dict[ord(data[pos + 0x13])]

            if bits != 0 and endian != "" and machine != "":
                file_type = "ELF%d (%s %s endian)" % (bits, machine, endian)
                output += "%s file found at offset %s.\n" % (file_type, hex(offset + pos))
                fi.setBookmark(offset + pos, 4, hex(offset + pos) + " " + file_type, "#c8ffff")
                found += 1

            i = pos + 4
    return (found, output)

def find_rtf_header(fi, data, offset, output):
    """
    Used by guess_multibyte_xor_keys()
    """
    i = 0
    pos = 0
    found = 0
    length = len(data)
    while i < length:
        pos = data.find("{\\rtf", i)
        if pos == -1:
            break
        else:
            output += "RTF header found at offset %s.\n" % hex(offset + pos)
            fi.setBookmark(offset + pos, 5, hex(offset + pos) + " RTF", "#c8ffff")
            i = pos + 5
            found += 1
    return (found, output)

def find_zip_header(fi, data, offset, output):
    """
    Used by guess_multibyte_xor_keys()
    """
    i = 0
    pos = 0
    found = 0
    length = len(data)
    while i < length:
        pos_start = data.find("PK\x03\x04", i)
        pos_end = data.find("PK\x05\x06", pos_start + 1)
        file_type = "ZIP" # default file type

        if pos_start == -1:
            break
        elif pos_end == -1:
            output += "ZIP local file header found at offset %s, but end of central directory record is missing.\n" % hex(offset + pos_start)
            fi.setBookmark(offset + pos_start, 4, hex(offset + pos_start) + " ZIP local file header", "#c8ffff")
            found += 1
            break
        elif data[pos_start + 30:pos_start + 49] == "[Content_Types].xml": # Possible Microsoft Office file
            pos_rels = data.find("PK\x03\x04", pos_start + 49)

            if pos_rels != -1 and data[pos_rels + 30:pos_rels + 41] == "_rels/.rels":
                pos_type = data.find("PK\x03\x04", pos_rels + 41)

                if pos_type != -1:
                    if data[pos_type + 30:pos_type + 34] == "word":
                        file_type = "Microsoft Word document"
                    elif data[pos_type + 30:pos_type + 33] == "ppt":
                        file_type = "Microsoft PowerPoint slide"
                    elif data[pos_type + 30:pos_type + 32] == "xl":
                        file_type = "Microsoft Excel spreadsheet"
        elif data[pos_start + 30:pos_start + 39] == "META-INF/": # Possible Java Archive (JAR) file
            pos_manifest = data.find("PK\x03\x04", pos_start + 39)

            if pos_manifest != -1 and data[pos_manifest + 30:pos_manifest + 50] == "META-INF/MANIFEST.MF":
                file_type = "Java Archive (JAR)"

        output += "%s found at offset %s size %d bytes.\n" % (file_type, hex(offset + pos_start), (pos_end - pos_start + 22))
        fi.setBookmark(offset + pos_start, pos_end - pos_start + 22, hex(offset + pos_start) + " " + file_type, "#c8ffff")
        i = pos_end + 22
        found += 1

    return (found, output)

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
        data = fi.getSelection()
        print('Top ten XOR keys guessed from offset %s to %s are shown in the new "Guessed XOR keys" tab.' % (hex(offset), hex(offset + length - 1)))
        print("Please select the whole file and use these XOR key in the Decode tab to decode the file.\n")
    else:
        offset = 0
        data = fi.getDocument()
        length = fi.getLength()
        print('Top ten XOR keys guessed from the whole file are shown in the new "Guessed XOR keys" tab.')
        print("Please select the whole file and use these XOR keys in the Decode tab to decode the file.\n")

    time_start = time.time()

    block = {}
    freq = {}
    for i in range(0, length, 256):
        # Do not use the first 256 byte as XOR key because it may contain a file header
        if i == 0 and offset == 0:
            continue

        b = data[i:i + 256]
        if len(b) == 256:
            h = hashlib.md5(b).hexdigest()
            if h not in block:
                block[h] = b
                freq[h] = 1
            else:
                freq[h] += 1

    output = ""
    i = 0
    for k, v in sorted(freq.items(), key=lambda x:x[1], reverse=True):
        if i < 10:
            key = shorten_xor_key(block[k])
            output += "XOR key: 0x"
            for j in range(len(key) - 1, -1, -1):
                output += "%02x" % ord(block[k][j])
            output += "\n"
            output += "256 bytes pattern occurrence count: %i\n" % v
            tmp = xor_with_multibyte_key(data, block[k])
            (num_pe, output) = find_pe_header(fi, tmp, offset, output)

            # pefile Python module is not installed
            if num_pe == -1:
                return

            (num_elf, output) = find_elf_header(fi, tmp, offset, output)
            (num_ole, output) = find_ole_header(fi, tmp, offset, output)
            (num_pdf, output) = find_pdf_header(fi, tmp, offset, output)
            (num_rtf, output) = find_rtf_header(fi, tmp, offset, output)
            (num_zip, output) = find_zip_header(fi, tmp, offset, output)
            if num_pe + num_elf + num_ole + num_pdf + num_rtf + num_zip == 1:
                output += "Added a bookmark to the search hit.\n"
            elif num_pe + num_elf + num_ole + num_pdf + num_rtf + num_zip > 1:
                output += "Added bookmarks to the search hits.\n"
            output += "\n"
            i += 1

    tab_name = fi.get_new_document_name("Guessed XOR keys")
    fi.newDocument(tab_name, 0)
    fi.setDocument(output)

    print("Elapsed time: %f (sec)" % (time.time() - time_start))

def visual_decrypt(fi):
    """
    Decode selected region with visual decrypt algorithm
    """
    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    if length > 0:
        data = list(fi.getDocument())

        # Do not show command prompt window
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        # Execute visual_encrypt_dialog.py to show GUI
        p = subprocess.Popen(["py.exe", "-3", "XOR/visual_encrypt_dialog.py"], startupinfo=startupinfo, stdout=subprocess.PIPE)

        # Get amount input
        stdout_data, stderr_data = p.communicate()

        if stdout_data == "":
            return

        key_length = int(stdout_data.rstrip())

        for i in range(offset + length - key_length, offset, -key_length):
            for j in range(key_length - 1, -1, -1):
                data[i + j] = chr(ord(data[i + j]) ^ ord(data[i + j - key_length]))

        tab_name = fi.get_new_document_name("Output of Visual Decrypt")
        fi.newDocument(tab_name, 1)
        fi.setDocument("".join(data))
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
        data = list(fi.getDocument())

        # Do not show command prompt window
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        # Execute visual_encrypt_dialog.py to show GUI
        p = subprocess.Popen(["py.exe", "-3", "XOR/visual_encrypt_dialog.py"], startupinfo=startupinfo, stdout=subprocess.PIPE)

        # Get amount input
        stdout_data, stderr_data = p.communicate()

        if stdout_data == "":
            return

        key_length = int(stdout_data.rstrip())

        for i in range(offset + key_length, offset + length, key_length):
            for j in range(0, key_length):
                data[i + j] = chr(ord(data[i + j]) ^ ord(data[i + j - key_length]))

        tab_name = fi.get_new_document_name("Output of Visual Encrypt")
        fi.newDocument(tab_name, 1)
        fi.setDocument("".join(data))
        fi.setBookmark(offset, length, hex(offset), "#c8ffff")

        if length == 1:
            print("Encoded one byte from offset %s to %s." % (hex(offset), hex(offset)))
        else:
            print("Encoded %s bytes from offset %s to %s." % (length, hex(offset), hex(offset + length - 1)))
        print("Added a bookmark to encoded region.")

def xor_with_another_file(fi):
    """
    XOR selected region (the whole file if not selected) while using the content of another file as XOR key
    """
    num_file = fi.getDocumentCount()
    if num_file < 2:
        if num_file == 1:
            print("Please open a file to be XORed and a XOR key file before using 'XOR with another file' plugin.")

        return

    file_list = ""
    current_file = fi.getDocumentName()
    current_file_index = 0
    for i in range(num_file):
        fi.activateDocumentAt(i)
        f = fi.getDocumentName()
        file_list += "%s\r\n" % f
        if current_file == f:
            current_file_index = i

    # Do not show command prompt window
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

    # Execute xor_with_another_file_dialog.py to show GUI
    p = subprocess.Popen(["py.exe", "-3", "XOR/xor_with_another_file_dialog.py"], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE)

    stdout_data, stderr_data = p.communicate(input=file_list)
    ret = p.wait()

    if stdout_data == "":
        fi.activateDocumentAt(current_file_index)
        return
    (xored_file_index, key_file_index) = stdout_data.split()

    fi.activateDocumentAt(int(xored_file_index))
    xored_filename = fi.getDocumentName()
    sel_len = fi.getSelectionLength()
    offset = fi.getSelectionOffset()

    data_len = fi.getLength()
    if data_len > 0:
        data = fi.getDocument()
        if sel_len == 0:
            sel_len = data_len
    else:
        fi.activateDocumentAt(current_file_index)
        print("%s is empty." % xored_filename)
        return

    if data == "":
        fi.activateDocumentAt(current_file_index)
        return
    else:
        data = list(data)

    fi.activateDocumentAt(int(key_file_index))
    key_filename = fi.getDocumentName()
    key_len = fi.getLength()
    if key_len > 0:
        key = fi.getDocument()

    if key_len == 0:
        fi.activateDocumentAt(current_file_index)
        print("XOR key file %s is empty." % key_filename)
        return
    else:
        key = list(key)

    for i in range(offset, offset + sel_len):
        data[i] = chr(ord(data[i]) ^ ord(key[(i - offset) % key_len]))

    tab_name = fi.get_new_document_name("Output of XOR with another file")
    fi.newDocument(tab_name, 1)
    fi.setDocument("".join(data))
    fi.setBookmark(offset, sel_len, hex(offset), "#c8ffff")

    if data_len == 1:
        print("XORed one byte in '%s' from offset %s to %s with the content of '%s'." % (xored_filename, hex(offset), hex(offset), key_filename))
    else:
        print("XORed %s bytes in '%s' from offset %s to %s with the content of '%s'." % (sel_len, xored_filename, hex(offset), hex(offset + sel_len - 1), key_filename))
    print("Added a bookmark to encoded region.")
