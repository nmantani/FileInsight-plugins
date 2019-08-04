#
# Search operations
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
import ctypes
import re
import subprocess
import string
import sys
import time

try:
    import yara
    yara_python_not_installed = False
except ImportError:
    yara_python_not_installed = True

def mask(x):
    """
    Masking bits
    Used by xor_hex_search() and xor_text_search()
    """
    if (x >= 0):
        return 2 ** x - 1
    else:
        return 0

def ror(x, rot=1):
    """
    Bitwise rotate right
    Used by xor_hex_search() and xor_text_search()
    """
    rot %= 8
    if (rot < 1):
        return x
    x &= mask(8)
    return (x >> rot) | ((x << (8 - rot)) & mask(8))

def rol(x, rot=1):
    """
    Bitwise rotate left
    Used by xor_hex_search() and xor_text_search()
    """
    rot %= 8
    if (rot < 1):
        return x
    x &= mask(8)
    return ((x << rot) & mask(8)) | (x >> (8 - rot))

def valdict(buf):
    """
    Make dictionary of values in data
    Used by xor_hex_search() and xor_text_search()
    """
    values = {}
    b = list(buf)
    length = len(b)

    for i in range(0, length):
        v = ord(buf[i])
        if (v not in values):
            values[v] = True

    return values

def search_xor_hex(fi, buf, offset, length, keyword):
    """
    Search XORed string
    Used by xor_hex_search()
    """
    LEN_AFTER_HIT = 30

    values = valdict(buf)
    num_hits = 0

    for i in range(0, length):
        v = ord(buf[i])
        if (v not in values):
            values[v] = True

    for i in range(0, 256):
        pattern = keyword[:]
        notinvalues = False
        hits = []

        # Encode search string and check whether the values of encoded string exist in data
        for j in range(0, len(pattern)):
            pattern[j] = chr(ord(pattern[j]) ^ i)
            if (ord(pattern[j]) not in values):
                notinvalues = True
                break

        # Skip search if the values of encoded string don't exist in data
        if (notinvalues):
            continue

        pos = buf.find("".join(pattern), 0)

        if (pos != -1):
            hits.append(pos)

        while (pos != -1):
            pos = buf.find("".join(pattern), pos + len(pattern))
            if (pos != -1):
                hits.append(pos)

        # Print search hits
        for j in hits:
            end = j + len(pattern) + LEN_AFTER_HIT
            if (end < length):
                hitstr = list(buf[j:end])
            else:
                hitstr = list(buf[j:])

            for k in range(0, len(hitstr)):
                c = ord(hitstr[k]) ^ i
                hitstr[k] = chr(c)

            hitstr = binascii.hexlify("".join(hitstr))
            hitstr = hitstr.upper()
            print "XOR key: 0x%02x offset: 0x%x search hit: %s" % (i, offset + j, hitstr)
            fi.setBookmark(offset + j, len(keyword), hex(offset + j), "#c8ffff")
            num_hits += 1

    return num_hits

def search_rol_hex(fi, buf, offset, length, keyword):
    """
    Search bit-rotated string
    Used by xor_hex_search()
    """
    LEN_AFTER_HIT = 30

    values = valdict(buf)
    num_hits = 0

    for i in range(1, 8):
        pattern = keyword[:]
        notinvalues = False
        hits = []

        # Encode search string and check whether the values of encoded string exist in data
        for j in range(0, len(pattern)):
            pattern[j] = chr(ror(ord(pattern[j]), i))
            if (ord(pattern[j]) not in values):
                notinvalues = True
                break

        # Skip search if the values of encoded string don't exist in data
        if (notinvalues):
            continue

        pos = buf.find("".join(pattern), 0)

        if (pos != -1):
            hits.append(pos)

        while (pos != -1):
            pos = buf.find("".join(pattern), pos + len(pattern))
            if (pos != -1):
                hits.append(pos)

        # Print search hits
        for j in hits:
            end = j + len(pattern) + LEN_AFTER_HIT
            if (end < length):
                hitstr = list(buf[j:end])
            else:
                hitstr = list(buf[j:])

            for k in range(0, len(hitstr)):
                c = rol(ord(hitstr[k]), i)
                hitstr[k] = chr(c)

            hitstr = binascii.hexlify("".join(hitstr))
            hitstr = hitstr.upper()
            print "ROL bit: %d offset: 0x%x search hit: %s" % (i, offset + j, hitstr)
            fi.setBookmark(offset + j, len(keyword), hex(offset + j), "#c8ffff")
            num_hits += 1

    return num_hits

def xor_hex_search(fi):
    """
    Search XORed / bit-rotated data in selected region (the whole file if not selected)
    """
    if fi.getDocumentCount() == 0:
        return

    length_sel = fi.getSelectionLength()
    offset = fi.getSelectionOffset()
    keyword = fi.showSimpleDialog("Search keyword (in hex):")
    keyword = keyword.replace("0x", "")
    disp_keyword = "0x" + keyword.lower()
    keyword = list(binascii.unhexlify(keyword))

    if (len(keyword) > 0):
        if (length_sel > 0):
            length = length_sel
            buf = fi.getSelection()
            print "Search XORed / bit-rotated data from offset %s to %s with keyword %s" % (hex(offset), hex(offset + length - 1), disp_keyword)
        else:
            buf = fi.getDocument()
            length = fi.getLength()
            offset = 0
            print "Search XORed / bit-rotated data in the whole file with keyword %s" % disp_keyword

        num_xor = search_xor_hex(fi, buf, offset, length, keyword)
        num_rol = search_rol_hex(fi, buf, offset, length, keyword)
        if num_xor + num_rol == 1:
            print "Added a bookmark to the search hit."
        elif num_xor + num_rol > 1:
            print "Added bookmarks to the search hits."

def search_xor_text(fi, buf, offset, length, keyword):
    """
    Search XORed string
    Used by xor_text_search()
    """
    LEN_AFTER_HIT = 50

    values = valdict(buf)
    num_hits = 0

    for i in range(0, length):
        v = ord(buf[i])
        if (v not in values):
            values[v] = True

    for i in range(0, 256):
        pattern = keyword[:]
        notinvalues = False
        hits = []

        # Encode search string and check whether the values of encoded string exist in data
        for j in range(0, len(pattern)):
            pattern[j] = chr(ord(pattern[j]) ^ i)
            if (ord(pattern[j]) not in values):
                notinvalues = True
                break

        # Skip search if the values of encoded string don't exist in data
        if (notinvalues):
            continue

        pos = buf.find("".join(pattern), 0)

        if (pos != -1):
            hits.append(pos)

        while (pos != -1):
            pos = buf.find("".join(pattern), pos + len(pattern))
            if (pos != -1):
                hits.append(pos)

        # Print search hits
        for j in hits:
            end = j + len(pattern) + LEN_AFTER_HIT
            if (end < length):
                hitstr = list(buf[j:end])
            else:
                hitstr = list(buf[j:])

            for k in range(0, len(hitstr)):
                c = ord(hitstr[k]) ^ i
                if (c < 0x20 or c > 0x126):
                    c = 0x2e
                hitstr[k] = chr(c)

            print "XOR key: 0x%02x offset: 0x%x search hit: %s" % (i, offset + j, "".join(hitstr))
            fi.setBookmark(offset + j, len(keyword), hex(offset + j), "#c8ffff")
            num_hits += 1

    return num_hits

def search_rol_text(fi, buf, offset, length, keyword):
    """
    Search bit-rotated string
    Used by xor_text_search()
    """
    LEN_AFTER_HIT = 50

    values = valdict(buf)
    num_hits = 0

    for i in range(1, 8):
        pattern = keyword[:]
        notinvalues = False
        hits = []

        # Encode search string and check whether the values of encoded string exist in data
        for j in range(0, len(pattern)):
            pattern[j] = chr(ror(ord(pattern[j]), i))
            if (ord(pattern[j]) not in values):
                notinvalues = True
                break

        # Skip search if the values of encoded string don't exist in data
        if (notinvalues):
            continue

        pos = buf.find("".join(pattern), 0)

        if (pos != -1):
            hits.append(pos)

        while (pos != -1):
            pos = buf.find("".join(pattern), pos + len(pattern))
            if (pos != -1):
                hits.append(pos)

        # Print search hits
        for j in hits:
            end = j + len(pattern) + LEN_AFTER_HIT
            if (end < length):
                hitstr = list(buf[j:end])
            else:
                hitstr = list(buf[j:])

            for k in range(0, len(hitstr)):
                c = rol(ord(hitstr[k]), i)
                if (c < 0x20 or c > 0x126):
                    c = 0x2e
                hitstr[k] = chr(c)

            print "ROL bit: %d offset: 0x%x search hit: %s" % (i, offset + j, "".join(hitstr))
            fi.setBookmark(offset + j, len(keyword), hex(offset + j), "#c8ffff")
            num_hits += 1

    return num_hits

def xor_text_search(fi):
    """
    Search XORed / bit-rotated string in selected region (the whole file if not selected)
    """
    if fi.getDocumentCount() == 0:
        return

    length_sel = fi.getSelectionLength()
    offset = fi.getSelectionOffset()
    keyword = list(fi.showSimpleDialog("Search keyword:"))

    if (len(keyword) > 0):
        if (length_sel > 0):
            length = length_sel
            buf = fi.getSelection()
            print "Search XORed / bit-rotated string from offset %s to %s with keyword '%s'" % (hex(offset), hex(offset + length - 1), "".join(keyword))
        else:
            buf = fi.getDocument()
            length = fi.getLength()
            offset = 0
            print "Search XORed / bit-rotated string in the whole file with keyword '%s'" % "".join(keyword)
        num_xor = search_xor_text(fi, buf, offset, length, keyword)
        num_rol = search_rol_text(fi, buf, offset, length, keyword)
        if num_xor + num_rol == 1:
            print "Added a bookmark to the search hit."
        elif num_xor + num_rol > 1:
            print "Added bookmarks to the search hits."

def is_printable(s):
    """
    Return True if 's' is printable string
    Used by regex_search(), replace() and yara_scan()
    """
    try:
        return all(c in string.printable for c in s)
    except TypeError:
        return False

def regex_search(fi):
    """
    Search with regular expression in selected region (the whole file if not selected)
    """
    if fi.getDocumentCount() == 0:
        return

    length_sel = fi.getSelectionLength()
    offset = fi.getSelectionOffset()
    if length_sel > 0:
        length = length_sel
        buf = fi.getSelection()
    else:
        buf = fi.getDocument()
        length = fi.getLength()
        offset = 0

    if buf == "":
        return

    keyword = fi.showSimpleDialog("Regular expression (please see https://docs.python.org/2.7/library/re.html for syntax):")

    time_start = time.time()

    if len(keyword) > 0:
        if length_sel > 0:
            print "Search from offset %s to %s with keyword '%s'\r\n" % (hex(offset), hex(offset + length - 1), keyword)
        else:
            print "Search in the whole file with keyword '%s'\r\n" % keyword

        try:
            re.compile(keyword)
        except:
            print "Error: invalid regular expression"
            return

        num_hits = 0
        match = re.finditer(keyword, buf)
        bookmark_start = []
        bookmark_end = []
        for m in match:
            if is_printable(m.group()):
                print "Offset: 0x%x Search hit: %s" % (offset + m.start(), re.sub("[\r\n\v\f]", "", m.group()))
            else:
                print "Offset: 0x%x Search hit: %s (hex)" % (offset + m.start(), binascii.hexlify(m.group()))
            if num_hits > 0 and offset + m.start() == bookmark_end[-1]:
                bookmark_end[-1] = offset + m.end()
            else:
                bookmark_start.append(offset + m.start())
                bookmark_end.append(offset + m.end())
            num_hits += 1

        print "\r\nElapsed time (search): %f (sec)" % (time.time() - time_start)
        time_start = time.time()

        for i in range(0, len(bookmark_start)):
            fi.setBookmark(bookmark_start[i], bookmark_end[i] - bookmark_start[i], hex(bookmark_start[i]), "#aaffaa")

        if num_hits == 1:
            print "Added a bookmark to the search hit."
        elif num_hits > 1:
            print "Added bookmarks to the search hits."

        print "Elapsed time (bookmark): %f (sec)" % (time.time() - time_start)

def replace(fi):
    """
    Replace matched data in selected region (the whole file if not selected) with specified data
    """
    if fi.getDocumentCount() == 0:
        return

    length_sel = fi.getSelectionLength()
    offset = fi.getSelectionOffset()

    if length_sel > 0:
        length = length_sel
        buf = fi.getSelection()
    else:
        buf = fi.getDocument()
        length = fi.getLength()
        offset = 0

    if buf == "":
        return

    # Do not show command prompt window
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

    # Execute send_to.py to show GUI
    # GUI portion is moved to send_to.py to avoid hangup of FileInsight
    p = subprocess.Popen(["python", "replace_dialog.py"], startupinfo=startupinfo, stdout=subprocess.PIPE)

    stdout_data, stderr_data = p.communicate()
    if stdout_data == "":
        return
    else:
        (keyword, replacement, mode, dummy) = stdout_data.split("\r\n")
        if keyword == "":
            return
        if mode == "Text":
            replacement_data = list(replacement)
        elif mode == "Hex":
            replacement_data = list(binascii.unhexlify(replacement))
        else:
            return
        replacement_len = len(replacement_data)

    time_start = time.time()

    if len(keyword) > 0:
        if length_sel > 0:
            print "Replace from offset %s to %s with keyword '%s' and replacement '%s'\r\n" % (hex(offset), hex(offset + length - 1), keyword, replacement)
        else:
            print "Replace in the whole file with keyword '%s' and replacement '%s'\r\n" % (keyword, replacement)

        try:
            re.compile(keyword)
        except:
            print "Error: invalid regular expression"
            return

        buf_list_all = list(fi.getDocument())
        buf_all_len = fi.getLength()
        if offset == 0:
            new_buf = []
        if offset > 0:
            new_buf = buf_list_all[:offset]

        num_hits = 0
        prev_pos = 0
        new_buf_len = 0
        bookmark_start = []
        bookmark_end = []
        match = re.finditer(keyword, buf)
        for m in match:
            new_buf.extend(buf_list_all[offset + prev_pos:offset + m.start()])
            new_buf.extend(replacement_data)
            prev_pos = m.end()
            new_buf_prev_len = new_buf_len
            new_buf_len += m.start() - prev_pos + replacement_len

            if is_printable(m.group()):
                print "Offset: 0x%x Search hit: %s" % (offset + m.start(), re.sub("[\r\n\v\f]", "", m.group()))
            else:
                print "Offset: 0x%x Search hit: %s (hex)" % (offset + m.start(), binascii.hexlify(m.group()))

            if num_hits > 0 and offset + new_buf_prev_len + m.start() == bookmark_end[-1]:
                bookmark_end[-1] = offset + new_buf_prev_len + m.start() + replacement_len
            else:
                bookmark_start.append(offset + new_buf_prev_len + m.start())
                bookmark_end.append(offset + new_buf_prev_len + m.start() + replacement_len)

            num_hits += 1

        print "\r\nElapsed time (replace): %f (sec)" % (time.time() - time_start)
        time_start = time.time()

        if num_hits > 0:
            if offset + m.end() < buf_all_len - 1:
                new_buf.extend(buf_list_all[offset + m.end():])

            fi.newDocument("New file", 1)
            fi.setDocument("".join(new_buf))

            for i in range(0, len(bookmark_start)):
                fi.setBookmark(bookmark_start[i], bookmark_end[i] - bookmark_start[i], hex(bookmark_start[i]), "#c8ffff")

        if num_hits == 1:
            print "Added a bookmark to the replaced data."
        elif num_hits > 1:
            print "Added bookmarks to the replaced data."

        print "Elapsed time (bookmark): %f (sec)" % (time.time() - time_start)

def yara_scan(fi):
    """
    Scan selected region (the whole file if not selected) with YARA
    """
    if yara_python_not_installed:
        print "yara-python is not installed."
        print "Please install it with 'python -m pip install yara-python' and restart FileInsight."
        return

    cp = ctypes.windll.kernel32.GetACP()
    cp = "cp%d" % cp

    num_file = fi.getDocumentCount()
    if num_file < 2:
        if num_file == 1:
            print "Please open a file to be scanned and a YARA rule file before using YARA scan plugin."

        return

    file_list = ""
    for i in range(num_file):
        fi.activateDocumentAt(i)
        file_list += "%s\r\n" % fi.getDocumentName().decode(cp).encode("utf-8")

    # Do not show command prompt window
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

    # Execute file_comparison_dialog.py to show GUI
    # GUI portion is moved to send_to.py to avoid hangup of FileInsight
    p = subprocess.Popen(["python", "yara_scan_dialog.py"], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE)

    stdout_data, stderr_data = p.communicate(input=file_list)
    if stdout_data == "":
        return
    (scanned_file_index, rule_file_index) = stdout_data.split()

    time_start = time.time()

    fi.activateDocumentAt(int(scanned_file_index))
    length_sel = fi.getSelectionLength()
    offset = fi.getSelectionOffset()
    if length_sel > 0:
        buf = fi.getSelection()
        buf_len = length_sel
    else:
        buf = fi.getDocument()
        buf_len = fi.getLength()
        offset = 0

    if buf == "":
        return

    fi.activateDocumentAt(int(rule_file_index))
    rule = fi.getDocument()

    try:
        y = yara.compile(source=rule)
    except Exception as e:
        print "Error: invalid YARA rule"
        print e
        return

    if length_sel > 0:
        print "Scan from offset %s to %s.\r\n" % (hex(offset), hex(offset + buf_len - 1))
    else:
        print "Scan the whole file.\r\n"

    match = y.match(data=buf)
    if len(match) == 0:
        print "No YARA rule matched."
        print "Elapsed time (scan): %f (sec)" % (time.time() - time_start)
        return

    num_hits = 0
    bookmark_start = []
    bookmark_end = []
    for m in match:
        prev_string = ""
        for i in range(0, len(m.strings)):
            if is_printable(m.strings[i][2]):
                print "Offset: 0x%x rule: %s tag: %s identifier: %s matched: %s" % (offset + m.strings[i][0], m.rule, " ".join(m.tags), m.strings[i][1], re.sub("[\r\n\v\f]", "", m.strings[i][2]))
            else:
                print "Offset: 0x%x rule: %s tag: %s identifier: %s matched: %s (hex)" % (offset + m.strings[i][0], m.rule, " ".join(m.tags), m.strings[i][1], binascii.hexlify(m.strings[i][2]))

            if num_hits > 0 and m.strings[i][1] == prev_string and offset + m.strings[i][0] <= bookmark_end[-1]:
                bookmark_end[-1] = offset + m.strings[i][0] + len(m.strings[i][2])
            else:
                bookmark_start.append(offset + m.strings[i][0])
                bookmark_end.append(offset + m.strings[i][0] + len(m.strings[i][2]))
            prev_string = m.strings[i][1]
            num_hits += 1

    print "\r\nElapsed time (scan): %f (sec)" % (time.time() - time_start)
    time_start = time.time()

    fi.activateDocumentAt(int(scanned_file_index))
    for i in range(0, len(bookmark_start)):
        fi.setBookmark(bookmark_start[i], bookmark_end[i] - bookmark_start[i], hex(bookmark_start[i]), "#aaffaa")

    if num_hits == 1:
        print "Added a bookmark to the search hit."
    elif num_hits > 1:
        print "Added bookmarks to the search hits."

    if num_hits > 0:
        print "Elapsed time (bookmark): %f (sec)" % (time.time() - time_start)
