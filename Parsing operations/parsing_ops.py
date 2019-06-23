#
# Parsing operations - Operations such as file type detection and embedded file
# detection
#
# Copyright (c) 2019, Nobutaka Mantani
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
import re
import struct
import subprocess
import sys
import time

try:
    sys.argv = [""]
    import binwalk
    binwalk_not_installed = False
except ImportError:
    binwalk_not_installed = True

try:
    import magic
    python_magic_not_installed = False
except ImportError:
    python_magic_not_installed = True

try:
    import pefile
    pefile_not_installed = False
except ImportError:
    pefile_not_installed = True

def binwalk_scan(fi):
    """
    Scan selected region (the whole file if not selected) to find embedded files
    """
    if binwalk_not_installed:
        print "binwalk is not installed."
        print "Please get it from https://github.com/ReFirmLabs/binwalk"
        print "(pip cannot be used to install binwalk)."
        return

    if fi.getDocumentCount() == 0:
        return

    length = fi.getSelectionLength()
    offset = fi.getSelectionOffset()

    offset_found = []
    if (length > 0):
        data = fi.getSelection()
        print "Scanned from offset %s to %s:" % (hex(offset), hex(offset + length))
    else:
        offset = 0
        data = fi.getDocument()
        length = fi.getLength()
        print "Scanned the whole file:"

    time_start = time.time()

    for module in binwalk.scan(data, signature=True, quiet=True, string=True):
        for result in module.results:
            print "Offset: 0x%x\t%s" % (offset + result.offset, result.description)
            offset_found.append(offset + result.offset)

    num_found = len(offset_found)
    if num_found == 0:
        print "No file has been detected."
    print "Elapsed time (scan): %f (sec)" % (time.time() - time_start)
    time_start = time.time()

    if num_found > 0:
        for i in range(0, num_found):
            if i + 1 == num_found:
                fi.setBookmark(offset_found[i], offset + length - offset_found[i], hex(offset_found[i]), "#c8ffff")
            else:
                fi.setBookmark(offset_found[i], offset_found[i + 1] - offset_found[i], hex(offset_found[i]), "#c8ffff")

        print "\r\nAdded bookmarks to the detected files."
        print "Elapsed time (bookmark): %f (sec)" % (time.time() - time_start)

def file_type(fi):
    """
    Identify file type of selected region (the whole file if not selected)
    """
    if python_magic_not_installed:
        print "python-magic is not installed."
        print "Please install it with 'python -m pip install python-magic-bin' and restart FileInsight."
        return

    length = fi.getSelectionLength()
    offset = fi.getSelectionOffset()

    if (length > 0):
        buf = fi.getSelection()
        type = magic.from_buffer(buf)
        print "File type from offset %s to %s: %s" % (hex(offset), hex(offset + length - 1), type)
    else:
        buf = fi.getDocument()
        type = magic.from_buffer(buf)
        print "File type of the whole file: %s" % type

def find_pe(fi, buf, offset):
    """
    Used by find_pe_file()
    """
    i = 0
    pos = 0
    found = 0
    valid_pe = False
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
                            print "Win32 DLL found at offset %s" % hex(offset + pos),
                        else:
                            print "Win32 executable found at offset %s" % hex(offset + pos),
                        valid_pe = True
                    elif buf[pos+pe_offset:pos+pe_offset+6] == "".join(['P', 'E', '\x00', '\x00', '\x64', '\x86']):
                        # Check characteristics
                        if struct.unpack("B", buf[pos+pe_offset+23])[0] & 0x20:
                            print "Win64 DLL found at offset %s" % hex(offset + pos),
                        else:
                            print "Win64 executable found at offset %s" % hex(offset + pos),
                        valid_pe = True

                    if valid_pe == True:
                        pe = pefile.PE(data=buf[pos:], fast_load=True)
                        pe_size = pe.OPTIONAL_HEADER.SizeOfHeaders
                        for section in pe.sections:
                            pe_size += section.SizeOfRawData
                        print "size %d bytes" % pe_size
                        if pos + pe_size > length:
                            print "The end of PE file (offset %s) is beyond the end of search region (offset %s). Bookmarked region will be truncated." % (hex(offset+pos+pe_size), hex(offset+length))
                            fi.setBookmark(offset + pos, length - pos, hex(offset + pos), "#c8ffff")
                        else:
                            fi.setBookmark(offset + pos, pe_size, hex(offset + pos), "#c8ffff")
                        found += 1
        valid_pe = False
        i = pos + 2
    return found

def find_pe_file(fi):
    """
    Find PE file from selected region (the whole file if not selected)
    """
    if pefile_not_installed:
        print "pefile is not installed."
        print "Please install it with 'python -m pip install pefile' and restart FileInsight."
        return

    if fi.getDocumentCount() == 0:
        return

    length = fi.getSelectionLength()
    offset = fi.getSelectionOffset()

    if (length > 0):
        buf = fi.getSelection()
        found = find_pe(fi, buf, offset)
        if found > 0:
            print "%d PE file(s) found from offset %s to %s." % (found, hex(offset), hex(offset + length - 1))
            print "Added bookmark(s) to the found PE file(s)."
        else:
            print "No PE file found from offset %s to %s." % (hex(offset), hex(offset + length - 1))
    else:
        offset = 0
        buf = fi.getDocument()
        length = fi.getLength()
        found = find_pe(fi, buf, offset)
        if found > 0:
            print "%d PE file(s) found from the whole file." % found
            print "Added bookmark(s) to the found PE file(s)."
        else:
            print "No PE file found from the whole file."

def strings_dedupe(matched, unicode, decode):
    """
    Used by strings()
    """
    unique = []
    for m in matched:
        if unicode:
            s = re.sub("\x00+", "", m.group())
            s = strings_decode_hex(s, decode)
        else:
            s = strings_decode_hex(m.group(), decode)
        unique.append(s)

    unique = list(set(unique))
    unique.sort()

    return unique

def strings_decode_hex(s, decode):
    """
    Used by strings() and strings_dedupe()
    """
    if decode:
        if re.match("^([0-9A-Fa-f]{2})+$", s):
            s_orig = s
            s = binascii.a2b_hex(s)
            if re.match("^[ -~]+$", s):
                return "Decoded: %s\tOriginal: %s" % (s, s_orig)
            elif re.match("^(?:(?:[ -~]\x00)|(?:\x00[ -~]))+$", s):
                s = re.sub("\x00", "", s)
                return "Decoded: %s\tOriginal: %s" % (s, s_orig)
            else:
                return s_orig
        else:
            return s
    else:
        return s

def strings(fi):
    """
    Extract text strings from selected region (the whole file if not selected)
    """
    if fi.getDocumentCount() == 0:
        return

    length = fi.getSelectionLength()
    offset = fi.getSelectionOffset()

    if (length > 0):
        data = fi.getSelection()
    else:
        offset = 0
        data = fi.getDocument()

    # Do not show command prompt window
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

    # Execute arc4_decrypt_dialog.py to show GUI
    # GUI portion is moved to external script to avoid hangup of FileInsight
    p = subprocess.Popen(["python", "strings_dialog.py"], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE)

    # Receive parameters
    stdout_data, stderr_data = p.communicate()
    if stdout_data == "":
        return

    stdout_data = stdout_data.rstrip()
    (mode, min_len, postprocess, decode_hex) = stdout_data.split("\t")
    min_len = int(min_len)
    if decode_hex == "True":
        decode_hex = True
    else:
        decode_hex = False
    newdata = ""

    if mode == "ASCII + UTF-16":
        expression = "[ -~]{%d,}" % min_len
        matched = re.finditer(expression, data)
        newdata += "ASCII strings:\r\n"
        if postprocess == "Remove duplicates":
            for d in strings_dedupe(matched, False, decode_hex):
                newdata += d + "\r\n"
        else:
            for m in matched:
                if postprocess == "Show offset":
                    newdata += "0x%x: %s\r\n" % (offset + m.start(), strings_decode_hex(m.group(), decode_hex))
                else:
                    newdata += strings_decode_hex(m.group(), decode_hex) + "\r\n"

        expression = "(?:(?:[ -~]\x00)|(?:\x00[ -~])){%d,}" % min_len
        matched = re.finditer(expression, data)
        newdata += "\nUTF-16 strings:\r\n"
        if postprocess == "Remove duplicates":
            for d in strings_dedupe(matched, True, decode_hex):
                newdata += d + "\r\n"
        else:
            for m in matched:
                s = re.sub("\x00+", "", m.group())
                if postprocess == "Show offset":
                    newdata += "0x%x: %s\r\n" % (offset + m.start(), strings_decode_hex(s, decode_hex))
                else:
                    newdata += strings_decode_hex(s, decode_hex) + "\r\n"
    elif mode == "ASCII":
        expression = "[ -~]{%d,}" % min_len
        matched = re.finditer(expression, data)
        newdata += "ASCII strings:\r\n"
        if postprocess == "Remove duplicates":
            for d in strings_dedupe(matched, False, decode_hex):
                newdata += d + "\r\n"
        else:
            for m in matched:
                if postprocess == "Show offset":
                    newdata += "0x%x: %s\r\n" % (offset + m.start(), strings_decode_hex(m.group(), decode_hex))
                else:
                    newdata += strings_decode_hex(m.group(), decode_hex) + "\r\n"
    elif mode == "UTF-16":
        expression = "(?:(?:[ -~]\x00)|(?:\x00[ -~])){%d,}" % min_len
        matched = re.finditer(expression, data)
        newdata += "UTF-16 strings:\r\n"
        if postprocess == "Remove duplicates":
            for d in strings_dedupe(matched, True, decode_hex):
                newdata += d + "\r\n"
        else:
            for m in matched:
                s = re.sub("\x00+", "", m.group())
                if postprocess == "Show offset":
                    newdata += "0x%x: %s\r\n" % (offset + m.start(), strings_decode_hex(s, decode_hex))
                else:
                    newdata += strings_decode_hex(s, decode_hex) + "\r\n"

    fi.newDocument("New file", 0) # Open a new tab with text mode
    fi.setDocument(newdata)

    if length > 0:
        print "Extracted text strings from offset %s to %s." % (hex(offset), hex(offset + length))
    else:
        print "Extracted text strings from the whole file."

    if decode_hex:
        print "Please search 'Decoded: ***\tOriginal: ***' lines to find decoded hex strings."
