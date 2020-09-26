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
import collections
import ctypes
import json
import os
import re
import struct
import subprocess
import sys
import tempfile
import time

def bookmark_yesno_dialog(num_bookmark):
    """
    Show a confirmation dialog of adding many bookmarks
    Used by binwalk_scan()
    """
    # Do not show command prompt window
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

    # Execute bookmark_yesno_dialog.py to show confirmation dialog
    p = subprocess.Popen(["py.exe", "-3", "Misc/bookmark_yesno_dialog.py", str(num_bookmark)], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE)

    # Receive scan result
    stdout_data, stderr_data = p.communicate()
    ret = p.wait()

    return ret

def binwalk_scan(fi):
    """
    Scan selected region (the whole file if not selected) to find embedded files
    """
    if fi.getDocumentCount() == 0:
        return

    time_start = time.time()

    length = fi.getSelectionLength()
    offset = fi.getSelectionOffset()

    offset_found = []
    if length > 0:
        data = fi.getSelection()
    else:
        offset = 0
        data = fi.getDocument()
        length = fi.getLength()

    # Create a temporary file
    fd, filepath = tempfile.mkstemp()
    handle = os.fdopen(fd, "wb")
    handle.write(data)
    handle.close()

    # Do not show command prompt window
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

    # Execute binwalk_scan.py for scanning with binwalk
    p = subprocess.Popen(["py.exe", "-3", "Parsing/binwalk_scan.py", filepath, str(offset)], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE)

    # Receive scan result
    stdout_data, stderr_data = p.communicate()
    ret = p.wait()

    os.remove(filepath) # Cleanup

    if ret == -1:
        print("binwalk is not installed.")
        print("Please get it from https://github.com/ReFirmLabs/binwalk and install it (pip cannot be used to install binwalk).")
        return

    if fi.getSelectionLength() > 0:
        print("Scanned from offset %s to %s:" % (hex(offset), hex(offset + length)))
    else:
        print("Scanned the whole file:")

    print(stdout_data),

    for l in stdout_data.splitlines():
        offset_found.append(int(l.split()[1], 0))

    num_found = len(offset_found)
    if num_found == 0:
        print("No file has been detected.")
    print("Elapsed time (scan): %f (sec)" % (time.time() - time_start))
    time_start = time.time()

    if num_found > 0:
        if num_found > 100 and not bookmark_yesno_dialog(num_found):
            return # "No" is clicked
        else:
            for i in range(0, num_found):
                if i + 1 == num_found:
                    fi.setBookmark(offset_found[i], offset + length - offset_found[i], hex(offset_found[i]), "#c8ffff")
                else:
                    fi.setBookmark(offset_found[i], offset_found[i + 1] - offset_found[i], hex(offset_found[i]), "#c8ffff")

            print("\r\nAdded bookmarks to the detected files.")
            print("Elapsed time (bookmark): %f (sec)" % (time.time() - time_start))

def file_type(fi):
    """
    Identify file type of selected region (the whole file if not selected)
    """
    length = fi.getSelectionLength()
    offset = fi.getSelectionOffset()

    if length > 0:
        data = fi.getSelection()
    else:
        data = fi.getDocument()

    # Do not show command prompt window
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

    # Execute file_type.py for file type identification
    p = subprocess.Popen(["py.exe", "-3", "Parsing/file_type.py"], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE)

    # Receive file type
    stdout_data, stderr_data = p.communicate(binascii.b2a_hex(data))
    ret = p.wait()

    if ret == -1:
        print("python-magic is not installed.")
        print("Please install it with 'py.exe -3 -m pip install python-magic-bin' and try again.")
        return

    ftype = stdout_data

    if length > 0:
        print("File type from offset %s to %s: %s" % (hex(offset), hex(offset + length - 1), ftype))
    else:
        print("File type of the whole file: %s" % ftype)

def find_pe_file(fi):
    """
    Find PE file from selected region (the whole file if not selected)
    """
    if fi.getDocumentCount() == 0:
        return

    length = fi.getSelectionLength()
    offset = fi.getSelectionOffset()

    if length > 0:
        data = fi.getSelection()
    else:
        offset = 0
        data = fi.getDocument()
        length = fi.getLength()

    # Do not show command prompt window
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

    # Execute find_pe_file.py for finding PE files
    p = subprocess.Popen(["py.exe", "-3", "Parsing/find_pe_file.py", str(offset)], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE)

    # Receive scan result
    stdout_data, stderr_data = p.communicate(binascii.b2a_hex(data))
    ret = p.wait()

    if ret == -1:
        print("pefile is not installed.")
        print("Please install it with 'py.exe -3 -m pip install pefile' and try again.")
        return

    found = ret
    print(stdout_data),

    for l in stdout_data.splitlines():
        if l[0:5] == "Win32" or l[0:5] == "Win64":
            off = int(l.split()[5], 0)
            size = int(l.split()[7], 0)
            if off + size > length:
                fi.setBookmark(off, length - off, hex(off), "#c8ffff")
            else:
                fi.setBookmark(off, size, hex(off), "#c8ffff")

    if fi.getSelectionLength() > 0:
        if found > 0:
            print("%d PE file(s) found from offset %s to %s." % (found, hex(offset), hex(offset + length - 1)))
            print("Added bookmark(s) to the found PE file(s).")
        else:
            print("No PE file found from offset %s to %s." % (hex(offset), hex(offset + length - 1)))
    else:
        if found > 0:
            print("%d PE file(s) found from the whole file." % found)
            print("Added bookmark(s) to the found PE file(s).")
        else:
            print("No PE file found from the whole file.")

def show_metadata(fi):
    """
    Show metadata of selected region (the whole file if not selected) with ExifTool
    """
    if fi.getDocumentCount() == 0:
        return

    length = fi.getSelectionLength()
    offset = fi.getSelectionOffset()

    if length > 0:
        data = fi.getSelection()
    else:
        offset = 0
        data = fi.getDocument()
        length = fi.getLength()

    if not os.path.exists("Parsing/exiftool.exe"):
        print("ExifTool is not installed.")
        print("Please download ExifTool from https://exiftool.org/")
        print("and copy exiftool(-k).exe as exiftool.exe into '%s' folder." % (os.getcwd() + "\\Parsing"))
        return

    # Create a temporary file
    fd, filepath = tempfile.mkstemp()
    handle = os.fdopen(fd, "wb")
    handle.write(data)
    handle.close()

    # Do not show command prompt window
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

    # Execute binwalk_scan.py for scanning with binwalk
    p = subprocess.Popen(["Parsing/exiftool.exe", filepath], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE)

    # Receive scan result
    stdout_data, stderr_data = p.communicate()
    ret = p.wait()

    os.remove(filepath) # Cleanup
    print(stdout_data),

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

    if length > 0:
        data = fi.getSelection()
    else:
        offset = 0
        data = fi.getDocument()

    # Do not show command prompt window
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

    # Execute strings_dialog.py to show GUI
    # GUI portion is moved to external script to avoid hangup of FileInsight
    p = subprocess.Popen(["py.exe", "-3", "Parsing/strings_dialog.py"], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE)

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

    fi.newDocument("Strings output", 0) # Open a new tab with text mode
    fi.setDocument(newdata)

    if length > 0:
        print("Extracted text strings from offset %s to %s." % (hex(offset), hex(offset + length)))
    else:
        print("Extracted text strings from the whole file.")

    if decode_hex:
        print("Please search 'Decoded: ***\tOriginal: ***' lines to find decoded hex strings.")

def bookmark_yesno_dialog(num_bookmark):
    """
    Show a confirmation dialog of adding many bookmarks
    Used by parse_file_structure()
    """
    # Do not show command prompt window
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

    # Execute bookmark_yesno_dialog.py to show confirmation dialog
    p = subprocess.Popen(["py.exe", "-3", "Misc/bookmark_yesno_dialog.py", str(num_bookmark)], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE)

    # Receive scan result
    stdout_data, stderr_data = p.communicate()
    ret = p.wait()

    return ret

def parse_file_structure(fi):
    """
    Parsing file structure from selected region (the whole file if not selected)
    """
    if fi.getDocumentCount() == 0:
        return

    length = fi.getSelectionLength()
    offset = fi.getSelectionOffset()

    if length > 0:
        data = fi.getSelection()
    else:
        offset = 0
        data = fi.getDocument()
        length = fi.getLength()

    # Do not show command prompt window
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

    # Structure for mouse cursor position
    class _point_t(ctypes.Structure):
        _fields_ = [
                    ("x",  ctypes.c_long),
                    ("y",  ctypes.c_long),
                   ]

    # Get DPI values
    DEFAULT_DPI = 96
    LOGPIXELSX = 88
    LOGPIXELSY = 90
    dc = ctypes.windll.user32.GetDC(0)
    dpi_x = ctypes.windll.gdi32.GetDeviceCaps(dc, LOGPIXELSX)
    dpi_y = ctypes.windll.gdi32.GetDeviceCaps(dc, LOGPIXELSY)
    ctypes.windll.user32.ReleaseDC(0, dc)

    # Get mouse cursor position
    point = _point_t()
    ctypes.windll.user32.GetCursorPos(ctypes.pointer(point))
    point.x = point.x * DEFAULT_DPI / dpi_x
    point.y = point.y * DEFAULT_DPI / dpi_y

    # Show menu
    p = subprocess.Popen(["py.exe", "-3", "Parsing/parse_file_structure_menu.py", str(point.x), str(point.y)], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # Receive selection
    stdout_data, stderr_data = p.communicate(binascii.b2a_hex(data))
    ret = p.wait()

    if stdout_data == "":
        return
    else:
        parser = stdout_data

    # Execute parse_file_structure.py to parse data
    p = subprocess.Popen(["py.exe", "-3", "Parsing/parse_file_structure.py", parser], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # Receive scan result
    stdout_data, stderr_data = p.communicate(binascii.b2a_hex(data))
    ret = p.wait()

    if ret == 1:
        print("Error: parse failed.")
        print(stderr_data)
        m = re.search(r": at pos (\d+):", stderr_data)
        if not m == None:
            failed_pos = int(m.group(1))
            fi.setBookmark(offset + failed_pos, 1, hex(offset + failed_pos) + " position of parse error", "#ff0000")
            print("Added bookmark to the position of parse error.")
        return

    if fi.getSelectionLength() > 0:
        print("Parsed from offset %s to %s as %s." % (hex(offset), hex(offset + length), parser))
    else:
        print("Parsed the whole file as %s." % parser)

    parsed_dict = json.loads(stdout_data, object_pairs_hook=collections.OrderedDict)
    parsed_dict = collections.OrderedDict(sorted(parsed_dict.items(), key=lambda x: x[1]["start"]))
    i = 0
    parsed_data = ""
    parsed_dict_len = len(parsed_dict)

    if parsed_dict_len > 100 and not bookmark_yesno_dialog(parsed_dict_len):
        do_bookmark = False
    else:
        do_bookmark = True

    for k in parsed_dict.keys():
        if do_bookmark:
            # Adjust start offset for one byte data
            if parsed_dict[k]["start"] - parsed_dict[k]["end"] == 1:
                parsed_dict[k]["start"] -= 1

            if i % 2 == 0:
                fi.setBookmark(offset + parsed_dict[k]["start"], parsed_dict[k]["end"] - parsed_dict[k]["start"] + 1, hex(offset + parsed_dict[k]["start"]) + " " + str(k), "#6d6dff")
            else:
                fi.setBookmark(offset + parsed_dict[k]["start"], parsed_dict[k]["end"] - parsed_dict[k]["start"] + 1, hex(offset + parsed_dict[k]["start"]) + " " + str(k), "#9f9fff")

        parsed_data += "%s - %s: %s -> %s\n" % (hex(offset + parsed_dict[k]["start"]), hex(offset + parsed_dict[k]["end"]), k, parsed_dict[k]["data"])
        i += 1

    if do_bookmark:
        print("Added bookmarks to the parsed data structure.")
    else:
        print("Skipped bookmarking.")

    fi.newDocument("Parsed data", 0)
    fi.setDocument("".join(parsed_data))
    print('Parsed data is shown in the new "Parsed data" tab.')
    print('Please use "Windows" tab -> "New Vertical Tab Group" to see parsed data and file contents side by side.')
    print(stderr_data)
