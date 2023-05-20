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

import base64
import binascii
import collections
import ctypes
import json
import os
import re
import subprocess
import tempfile
import time

def binwalk_scan(fi):
    """
    Scan selected region (the whole file if not selected) to find embedded files
    """
    if fi.getDocumentCount() == 0:
        print("Please open a file to use this plugin.")
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
    p = subprocess.Popen([fi.get_embed_python(), "Parsing/binwalk_scan.py", filepath, str(offset)], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE)

    # Receive scan result
    stdout_data, stderr_data = p.communicate()
    ret = p.wait()

    os.remove(filepath) # Cleanup

    if ret == -1:
        print("binwalk Python module is not installed.")
        print("Please install it with the following commands and try again.")
        print("&'%s' -m pip install https://github.com/ReFirmLabs/binwalk/archive/refs/tags/v2.3.2.zip" % fi.get_embed_python())
        return

    if fi.getSelectionLength() > 0:
        print('Scanned from offset %s to %s and the output is shown in the new "Binwalk output" tab.' % (hex(offset), hex(offset + length)))
    else:
        print('Scanned the whole file and the output is shown in the new "Binwalk output" tab.')

    for l in stdout_data.splitlines():
        offset_found.append(int(l.split()[1], 0))

    num_found = len(offset_found)
    if num_found == 0:
        print("No file has been detected.")

    print("Elapsed time (scan): %f (sec)" % (time.time() - time_start))
    time_start = time.time()

    if num_found > 0:
        if num_found > 100 and not fi.bookmark_yesno_dialog(num_found):
            # "No" is clicked
            tab_name = fi.get_new_document_name("Binwalk output")
            fi.newDocument(tab_name, 0)
            fi.setDocument(stdout_data)
        else:
            for i in range(0, num_found):
                if i + 1 == num_found:
                    fi.setBookmark(offset_found[i], offset + length - offset_found[i], hex(offset_found[i]), "#c8ffff")
                else:
                    fi.setBookmark(offset_found[i], offset_found[i + 1] - offset_found[i], hex(offset_found[i]), "#c8ffff")

            print("\r\nAdded bookmarks to the detected files.")
            print("Elapsed time (bookmark): %f (sec)" % (time.time() - time_start))

            tab_name = fi.get_new_document_name("Binwalk output")
            fi.newDocument(tab_name, 0)
            fi.setDocument(stdout_data)

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
    p = subprocess.Popen([fi.get_embed_python(), "Parsing/file_type.py"], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE)

    # Receive file type
    stdout_data, stderr_data = p.communicate(data)
    ret = p.wait()

    if ret == -1:
        fi.show_module_install_instruction("magic", "python-magic-bin")
        return

    file_type_python_magic = stdout_data

    if not os.path.exists("Parsing/die_win64_portable/diec.exe"):
        print("Detect It Easy is not installed.")
        print("Please download die_win64_portable_****.zip from https://github.com/horsicq/DIE-engine/releases")
        print("and extract files into '%s' folder." % (os.getcwd() + "\\Parsing\\die_win64_portable"))
        return

    # Create a temporary file
    fd, filepath = tempfile.mkstemp()
    handle = os.fdopen(fd, "wb")
    handle.write(data)
    handle.close()

    # Do not show command prompt window
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

    # Execute diec.exe for file type identification
    p = subprocess.Popen(["Parsing/die_win64_portable/diec.exe", filepath], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE)

    # Receive scan result
    stdout_data, stderr_data = p.communicate()
    ret = p.wait()

    file_type_die = stdout_data

    os.remove(filepath) # Cleanup

    if length > 0:
        print("File type from offset %s to %s:" % (hex(offset), hex(offset + length - 1)))
        print("[File type identified with python-magic]")
        print(file_type_python_magic)
        print("[File type identified with Detect It Easy]")
        print(file_type_die)
    else:
        print("File type of the whole file:")
        print("[File type identified with python-magic]")
        print(file_type_python_magic)
        print("[File type identified with Detect It Easy]")
        print(file_type_die)

def find_pe_file(fi):
    """
    Find PE file from selected region (the whole file if not selected) based on PE header information
    """
    if fi.getDocumentCount() == 0:
        print("Please open a file to use this plugin.")
        return

    length = fi.getSelectionLength()
    offset = fi.getSelectionOffset()

    if length > 0:
        data = fi.getSelection()
        orig = fi.getDocument()
    else:
        offset = 0
        data = fi.getDocument()
        length = fi.getLength()

    # Do not show command prompt window
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

    # Execute find_pe_file.py for finding PE files
    p = subprocess.Popen([fi.get_embed_python(), "Parsing/find_pe_file.py", str(offset)], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE)

    # Receive scan result
    stdout_data, stderr_data = p.communicate(data)
    ret = p.wait()

    if ret == -1:
        fi.show_module_install_instruction("pefile")
        return

    found = ret
    print(stdout_data),

    offset_missing_mz = []
    for l in stdout_data.splitlines():
        if l[0:5] == "Win32" or l[0:5] == "Win64":
            filetype = " ".join(l.split()[0:2])
            off = int(l.split()[5], 0)
            size = int(l.split()[7], 0)
            if off + size > length:
                fi.setBookmark(off, length - off, hex(off) + ": " + filetype, "#c8ffff")
            else:
                fi.setBookmark(off, size, hex(off) + ": " + filetype, "#c8ffff")
            if '"MZ" signature is missing at offset' in l:
                fi.setBookmark(off, 2, hex(off) + ': Added "MZ" signature', "#c8ffff")
                offset_missing_mz.append(off)

    if len(offset_missing_mz) > 0:
        if fi.getSelectionLength() > 0:
            newdata = list(fi.getDocument())
        else:
            newdata = list(data)

        for off in offset_missing_mz:
            newdata[off] = "M"
            newdata[off + 1] = "Z"

        newdata = "".join(newdata)
        fi.setDocument(newdata)

    if fi.getSelectionLength() > 0:
        if found > 0:
            print("%d PE file(s) found from offset %s to %s." % (found, hex(offset), hex(offset + length - 1)))
            if len(offset_missing_mz) > 0:
                print('Added bookmark(s) to the found PE file(s) and the added "MZ" signature(s).')
            else:
                print("Added bookmark(s) to the found PE file(s).")
        else:
            print("No PE file found from offset %s to %s." % (hex(offset), hex(offset + length - 1)))
    else:
        if found > 0:
            print("%d PE file(s) found from the whole file." % found)
            if len(offset_missing_mz) > 0:
                print('Added bookmark(s) to the found PE file(s) and the added "MZ" signature(s).')
            else:
                print("Added bookmark(s) to the found PE file(s).")
        else:
            print("No PE file found from the whole file.")

def show_metadata(fi):
    """
    Show metadata of selected region (the whole file if not selected) with ExifTool
    """
    if fi.getDocumentCount() == 0:
        print("Please open a file to use this plugin.")
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

    # Execute exiftool.exe to get metadata
    p = subprocess.Popen(["Parsing/exiftool.exe", filepath], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE)

    # Receive scan result
    stdout_data, stderr_data = p.communicate()
    ret = p.wait()

    os.remove(filepath) # Cleanup

    tab_name = fi.get_new_document_name("Metadata")
    fi.newDocument(tab_name, 0)
    fi.setDocument(stdout_data)

    print('Metadata is shown in the new "%s" tab.' % tab_name)

def strings_dedupe(matched, unicode, decode):
    """
    Used by strings()
    """
    plain = []
    decoded = []
    for m in matched:
        if unicode:
            s = re.sub("\x00+", "", m.group())
            (s_plain, s_decoded) = strings_decode(s, decode)
        else:
            (s_plain, s_decoded) = strings_decode(m.group(), decode)
        plain.append(s_plain)
        if s_decoded != "":
            decoded.append("%s -> %s" % (s_plain, s_decoded))

    plain = list(set(plain))
    plain.sort()
    decoded = list(set(decoded))
    decoded.sort()

    return plain, decoded

def strings_decode(s, decode):
    """
    Used by strings() and strings_dedupe()
    """
    if decode:
        if re.match("^([0-9A-Fa-f]{2})+$", s):
            s_orig = s
            s = binascii.a2b_hex(s)
            if re.match("^[ -~]+$", s):
                return s_orig, s
            elif re.match("^(?:(?:[ -~]\x00)|(?:\x00[ -~]))+$", s):
                s = re.sub("\x00", "", s)
                return s_orig, s
            else:
                return s_orig, ""
        elif re.match("^[0-9A-Za-z/+]+=*$", s):
            s_orig = s

            try:
                s = base64.b64decode(s_orig)
            except:
                s = ""

            if re.match("^[ -~]+$", s):
                return s_orig, s
            elif re.match("^(?:(?:[ -~]\x00)|(?:\x00[ -~]))+$", s):
                s = re.sub("\x00", "", s)
                return s_orig, s
            else:
                return s_orig, ""
        else:
            return s, ""
    else:
        return s, ""

def strings(fi):
    """
    Extract text strings from selected region (the whole file if not selected)
    """
    if fi.getDocumentCount() == 0:
        print("Please open a file to use this plugin.")
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
    p = subprocess.Popen([fi.get_embed_python(), "Parsing/strings_dialog.py"], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE)

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
    decoded = ""

    if mode == "ASCII + UTF-16":
        expression = "[ -~]{%d,}" % min_len
        matched = re.finditer(expression, data)
        newdata += "ASCII strings:\r\n"
        decoded += "Decoded ASCII strings:\r\n"

        if postprocess == "Remove duplicates":
            (plain_list, decoded_list) = strings_dedupe(matched, False, decode_hex)
            for s_plain in plain_list:
                newdata += s_plain + "\r\n"
            for s_decoded in decoded_list:
                decoded += s_decoded + "\r\n"
        else:
            for m in matched:
                (s_plain, s_decoded) = strings_decode(m.group(), decode_hex)

                if postprocess == "Show offset":
                    newdata += "0x%x: %s\r\n" % (offset + m.start(), s_plain)
                    if s_decoded != "":
                        decoded += "0x%x: %s -> %s\r\n" % (offset + m.start(), s_plain, s_decoded)
                else:
                    newdata += s_plain + "\r\n"
                    if s_decoded != "":
                        decoded += "%s -> %s \r\n" % (s_plain, s_decoded)

        expression = "(?:(?:[ -~]\x00)|(?:\x00[ -~])){%d,}" % min_len
        matched = re.finditer(expression, data)
        newdata += "\r\nUTF-16 strings:\r\n"
        decoded += "\r\nDecoded UTF-16 strings:\r\n"

        if postprocess == "Remove duplicates":
            (plain_list, decoded_list) = strings_dedupe(matched, True, decode_hex)
            for s_plain in plain_list:
                newdata += s_plain + "\r\n"
            for s_decoded in decoded_list:
                decoded += s_decoded + "\r\n"
        else:
            for m in matched:
                s = re.sub("\x00+", "", m.group())
                (s_plain, s_decoded) = strings_decode(s, decode_hex)

                if postprocess == "Show offset":
                    newdata += "0x%x: %s\r\n" % (offset + m.start(), s_plain)
                    if s_decoded != "":
                        decoded += "0x%x: %s -> %s\r\n" % (offset + m.start(), s_plain, s_decoded)
                else:
                    newdata += s_plain + "\r\n"
                    if s_decoded != "":
                        decoded += "%s -> %s \r\n" % (s_plain, s_decoded)
    elif mode == "ASCII":
        expression = "[ -~]{%d,}" % min_len
        matched = re.finditer(expression, data)
        newdata += "ASCII strings:\r\n"
        decoded += "Decoded ASCII strings:\r\n"

        if postprocess == "Remove duplicates":
            (plain_list, decoded_list) = strings_dedupe(matched, False, decode_hex)
            for s_plain in plain_list:
                newdata += s_plain + "\r\n"
            for s_decoded in decoded_list:
                decoded += s_decoded + "\r\n"
        else:
            for m in matched:
                (s_plain, s_decoded) = strings_decode(m.group(), decode_hex)

                if postprocess == "Show offset":
                    newdata += "0x%x: %s\r\n" % (offset + m.start(), s_plain)
                    if s_decoded != "":
                        decoded += "0x%x: %s -> %s\r\n" % (offset + m.start(), s_plain, s_decoded)
                else:
                    newdata += s_plain + "\r\n"
                    if s_decoded != "":
                        decoded += "%s -> %s \r\n" % (s_plain, s_decoded)
    elif mode == "UTF-16":
        expression = "(?:(?:[ -~]\x00)|(?:\x00[ -~])){%d,}" % min_len
        matched = re.finditer(expression, data)
        newdata += "UTF-16 strings:\r\n"
        decoded += "Decoded UTF-16 strings:\r\n"

        if postprocess == "Remove duplicates":
            (plain_list, decoded_list) = strings_dedupe(matched, True, decode_hex)
            for s_plain in plain_list:
                newdata += s_plain + "\r\n"
            for s_decoded in decoded_list:
                decoded += s_decoded + "\r\n"
        else:
            for m in matched:
                s = re.sub("\x00+", "", m.group())
                (s_plain, s_decoded) = strings_decode(s, decode_hex)

                if postprocess == "Show offset":
                    newdata += "0x%x: %s\r\n" % (offset + m.start(), s_plain)
                    if s_decoded != "":
                        decoded += "0x%x: %s -> %s\r\n" % (offset + m.start(), s_plain, s_decoded)
                else:
                    newdata += s_plain + "\r\n"
                    if s_decoded != "":
                        decoded += "%s -> %s \r\n" % (s_plain, s_decoded)

    tab_name = fi.get_new_document_name("Strings output")
    fi.newDocument(tab_name, 0) # Open a new tab with text mode
    if decode_hex:
        fi.setDocument(decoded + "\r\n" + newdata)
    else:
        fi.setDocument(newdata)

    if length > 0:
        print("Extracted text strings from offset %s to %s." % (hex(offset), hex(offset + length)))
    else:
        print("Extracted text strings from the whole file.")

def parse_file_structure(fi):
    """
    Parsing file structure from selected region (the whole file if not selected)
    """
    if fi.getDocumentCount() == 0:
        print("Please open a file to use this plugin.")
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
    p = subprocess.Popen([fi.get_embed_python(), "Parsing/parse_file_structure_menu.py", str(point.x), str(point.y)], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # Receive selection
    stdout_data, stderr_data = p.communicate()
    ret = p.wait()

    if stdout_data == "":
        return
    else:
        parser = stdout_data

    # Execute parse_file_structure.py to parse data
    p = subprocess.Popen([fi.get_embed_python(), "Parsing/parse_file_structure.py", parser], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # Receive scan result
    stdout_data, stderr_data = p.communicate(data)
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
    parsed_data_list = []
    parsed_dict_len = len(parsed_dict)

    if parsed_dict_len > 100 and not fi.bookmark_yesno_dialog(parsed_dict_len):
        do_bookmark = False
    else:
        do_bookmark = True

    for k in parsed_dict.keys():
        # For the case that start offset is larger than end offset
        if parsed_dict[k]["start"] > parsed_dict[k]["end"]:
            parsed_dict[k]["start"] = parsed_dict[k]["end"]

        if do_bookmark:
            # Adjust start offset for one byte data
            if parsed_dict[k]["start"] - parsed_dict[k]["end"] == 1:
                parsed_dict[k]["start"] -= 1

            if parsed_dict[k]["start"] < 0:
                parsed_dict[k]["start"] = 0

            if parsed_dict[k]["end"] < 0:
                parsed_dict[k]["end"] = 0

            if i % 2 == 0:
                fi.setBookmark(offset + parsed_dict[k]["start"], parsed_dict[k]["end"] - parsed_dict[k]["start"] + 1, hex(offset + parsed_dict[k]["start"]) + " " + str(k), "#6d6dff")
            else:
                fi.setBookmark(offset + parsed_dict[k]["start"], parsed_dict[k]["end"] - parsed_dict[k]["start"] + 1, hex(offset + parsed_dict[k]["start"]) + " " + str(k), "#9f9fff")

        parsed_data_list.append((("%s - %s: %s -> %s\n" % (hex(offset + parsed_dict[k]["start"]), hex(offset + parsed_dict[k]["end"]), k, parsed_dict[k]["data"])), parsed_dict[k]["start"], parsed_dict[k]["end"]))
        i += 1

    parsed_data_list.sort(key=lambda x:(x[1], x[2], x[0]))

    parsed_data = ""
    for p in parsed_data_list:
        parsed_data += p[0]

    if do_bookmark:
        print("Added bookmarks to the parsed data structure.")
    else:
        print("Skipped bookmarking.")

    tab_name = fi.get_new_document_name("Parsed data")
    fi.newDocument(tab_name, 0)

    fi.setDocument(parsed_data.encode("UTF-8"))
    print('Parsed data is shown in the new "Parsed data" tab.')
    print('Please use "Windows" tab -> "New Vertical Tab Group" to see parsed data and file contents side by side.')
    print(stderr_data)

def disassemble(fi):
    """
    Disassemble selected region (the whole file if not selected)
    """
    if fi.getDocumentCount() == 0:
        print("Please open a file to use this plugin.")
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

    # Execute disassemble_dialog.py to show GUI
    p = subprocess.Popen([fi.get_embed_python(), "Parsing/disassemble_dialog.py"], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    stdout_data, stderr_data = p.communicate()
    ret = p.wait()

    # Capstone is not installed
    if ret == -1:
        fi.show_module_install_instruction("capstone")
        return

    # dialog is closed
    if stdout_data == "":
        return

    # Get parameters from disassemble_dialog.py
    (arch, mode) = stdout_data.split("\t")
    disasm_setting = stderr_data

    # Create a temporary file to write data
    fd, file_path = tempfile.mkstemp()
    handle = os.fdopen(fd, "wb")
    handle.write(data)
    handle.close()

    p = subprocess.Popen([fi.get_embed_python(), "Parsing/disassemble.py", file_path, str(offset), arch, mode], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # Receive disassembly result
    stdout_data, stderr_data = p.communicate()
    ret = p.wait()

    os.remove(file_path) # Cleanup temporary file

    # disassembly.py exited with error
    if ret == 1:
        print(stderr_data.replace("\x0d\x0a", "\x0a")),
        return
    elif ret == -1: # Capstone is not installed
        fi.show_module_install_instruction("capstone")
        return

    if fi.getSelectionLength() > 0:
        print("Disassembled from offset %s to %s." % (hex(offset), hex(offset + length)))
    else:
        print("Disassembled the whole file.")
    print('Disassembly code is shown in the new "Disassembly" tab.')

    # Show disassembly settings
    print(disasm_setting),

    if not stderr_data == "":
        end_pos = int(stderr_data)
        fi.setBookmark(end_pos, 1, hex(end_pos) + " end of disassembly", "#ff0000")
        print("Disassembly finished prematurely at offset %s." % hex(end_pos))
        print("Added bookmark to the end of disassembly.")

    tab_name = fi.get_new_document_name("Disassembly")
    fi.newDocument(tab_name, 0)
    fi.setDocument("".join(stdout_data))

def extract_vba_macro(fi):
    """
    Extract Microsoft Office VBA macro from selected region (the whole file if not selected)
    """
    if fi.getDocumentCount() == 0:
        print("Please open a file to use this plugin.")
        return

    length = fi.getSelectionLength()
    offset = fi.getSelectionOffset()

    if length > 0:
        data = fi.getSelection()
        selection = True
    else:
        offset = 0
        data = fi.getDocument()
        length = fi.getLength()
        selection = False

    # Do not show command prompt window
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

    # Execute extract_vba_macro_dialog.py to show GUI
    p = subprocess.Popen([fi.get_embed_python(), "Parsing/extract_vba_macro_dialog.py", "-e"], startupinfo=startupinfo, stdout=subprocess.PIPE)

    # Get extraction setting
    stdout_data, stderr_data = p.communicate()
    if stdout_data == "":
        return

    method, retry = stdout_data.rstrip().split("\t")

    if retry == "True":
        retry = True
    else:
        retry = False

    # Execute extract_vba_macro.py to check VBA stomping
    p = subprocess.Popen([fi.get_embed_python(), "Parsing/extract_vba_macro.py", "-c"], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # Receive result
    stdout_data, stderr_data = p.communicate(data)
    ret = p.wait()

    if ret == -1: # oletools is not installed
        fi.show_module_install_instruction("oletools")
        return
    elif ret == -2: # Binary Refinery is not installed
        fi.show_module_install_instruction("refinery", "binary-refinery")
        return

    if ret == 1:
        vba_stomping = True
    elif stderr_data != "" and not "Input data not recognized by VBA parser" in stderr_data:
        if fi.getSelectionLength() > 0:
            print("No VBA macro found from offset %s to %s." % (hex(offset), hex(offset + length)))
        else:
            print("No VBA macro found from the whole file.")

        return
    else:
        vba_stomping = False

    if method == "Extract source code":
        extract_vba_source(fi, data, offset, length, selection)
    else:
        decompile_pcode(fi, data, offset, length, selection)

    if vba_stomping:
        if retry:
            print("VBA stomping has been detected. Trying another extraction method because VBA source code or p-code may be altered.")
            if method == "Extract source code":
                decompile_pcode(fi, data, offset, length, selection)
            else:
                extract_vba_source(fi, data, offset, length, selection)
        else:
            print("VBA stomping has been detected. VBA source or p-code may be altered.")
    else:
        print("VBA stomping has not been detected.")

def extract_vba_source(fi, data, offset, length, selection):
    """
    Used by extract_vba_macro()
    """

    # Do not show command prompt window
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

    # Execute extract_vba_macro.py to extract VBA macro
    p = subprocess.Popen([fi.get_embed_python(), "Parsing/extract_vba_macro.py"], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # Receive result
    stdout_data, stderr_data = p.communicate(data)
    ret = p.wait()

    if stderr_data != "" and not "Input data not recognized by VBA parser" in stderr_data:
        print("Error: parse failed.")
        print(stderr_data)
        return False
    elif stdout_data == "":
        if selection:
            print("No VBA macro found from offset %s to %s." % (hex(offset), hex(offset + length)))
        else:
            print("No VBA macro found from the whole file.")

        return False
    else:
        tab_name = fi.get_new_document_name("Extracted VBA macro (from source)")
        fi.newDocument(tab_name, 0)
        fi.setDocument(stdout_data)

        if selection:
            print('Extracted VBA macro source code from offset %s to %s and the output is shown in the new "%s" tab.' % (hex(offset), hex(offset + length), tab_name))
        else:
            print('Extracted VBA macro source code from the whole file and the output is shown in the new "%s" tab.' % tab_name)

    return True

def decompile_pcode(fi, data, offset, length, selection):
    """
    Used by extract_vba_macro()
    """

    # Do not show command prompt window
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

    # Execute extract_vba_macro.py to extract VBA macro
    p = subprocess.Popen([fi.get_embed_python(), "Parsing/extract_vba_macro.py", "-p"], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # Receive result
    stdout_data, stderr_data = p.communicate(data)
    ret = p.wait()

    if stderr_data != "" and not "not a supported file type" in stderr_data:
        print("Error: parse failed.")
        print(stderr_data)
        return
    elif stdout_data == "":
        if selection:
            print("No VBA macro found from offset %s to %s." % (hex(offset), hex(offset + length)))
        else:
            print("No VBA macro found from the whole file.")
        return
    else:
        tab_name = fi.get_new_document_name("Extracted VBA macro (from p-code)")
        fi.newDocument(tab_name, 0)
        fi.setDocument(stdout_data)

        if selection:
            print('Decompiled VBA macro p-code from offset %s to %s and the output is shown in the new "%s" tab.' % (hex(offset), hex(offset + length), tab_name))
        else:
            print('Decompiled VBA macro p-code from the whole file and the output is shown in the new "%s" tab.' % tab_name)

def string_type(fi):
    """
    Identify type of strings such as API keys and cryptocurrency wallet addresses
    in the selected region (the whole file if not selected) with lemmeknow
    """
    if fi.getDocumentCount() == 0:
        print("Please open a file to use this plugin.")
        return

    length = fi.getSelectionLength()
    offset = fi.getSelectionOffset()

    if length > 0:
        data = fi.getSelection()
        selection = True
    else:
        offset = 0
        data = fi.getDocument()
        length = fi.getLength()
        selection = False

    if not os.path.exists("Parsing/lemmeknow-windows.exe"):
        print("lemmeknow is not installed.")
        print("Please download lemmeknow-windows.exe from https://github.com/swanandx/lemmeknow/releases")
        print("and copy it into '%s' folder." % (os.getcwd() + "\\Parsing"))
        return

    # Do not show command prompt window
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

    # Execute string_type_dialog.py to show GUI
    p = subprocess.Popen([fi.get_embed_python(), "Parsing/string_type_dialog.py"], startupinfo=startupinfo, stdout=subprocess.PIPE)

    # Get boundaryless mode setting
    stdout_data, stderr_data = p.communicate()
    ret = p.wait()

    if stdout_data == "":
        return
    else:
        stdout_data = stdout_data.rstrip()

    if stdout_data == "True":
        command = ["Parsing/lemmeknow-windows.exe", "-j"]
        boundaryless = "enabled"
    else:
        command = ["Parsing/lemmeknow-windows.exe", "-b", "-j"]
        boundaryless = "disabled"

    # Create a temporary file
    fd, filepath = tempfile.mkstemp()
    handle = os.fdopen(fd, "wb")
    handle.write(data)
    handle.close()

    command += [filepath]

    # Execute lemmeknow-windows.exe to identify type of strings
    p = subprocess.Popen(command, startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE)

    # Receive identified strings
    stdout_data, stderr_data = p.communicate()
    ret = p.wait()

    os.remove(filepath) # Cleanup

    identified_strings = json.loads(stdout_data, object_pairs_hook=collections.OrderedDict)

    max_text_len = 0
    max_name_len = 0
    len_upperbound = 60
    column_space = 8
    for s in identified_strings:
        if len(s["text"]) > max_text_len:
            max_text_len = len(s["text"])

        if len(s["data"]["name"]) > max_name_len:
            max_name_len = len(s["data"]["name"])

    if fi.getSelectionLength() > 0:
        print("Strings from offset %s to %s has been identified (boundaryless mode = %s)." % (hex(offset), hex(offset + length - 1), boundaryless))
    else:
        print("Strings of the whole has been identified (boundaryless mode = %s)." % boundaryless)

    if max_text_len == 0 or max_name_len == 0:
        print("No string has been identified as a specific type.")
        return
    else:
        if max_text_len > len_upperbound:
            max_text_len = len_upperbound

        if max_name_len > len_upperbound:
            max_name_len = len_upperbound

    output = "String" + " " * (max_text_len - len("String") + column_space)
    output += "Type\n"
    output += "-" * (max_text_len + column_space + max_name_len) + "\n"

    for s in identified_strings:
        if len(s["text"]) > len_upperbound or len(s["data"]["name"]) > len_upperbound:
            split_text = [s["text"][i:i+len_upperbound] for i in range(0, len(s["text"]), len_upperbound)]
            split_name = [s["data"]["name"][i:i+len_upperbound] for i in range(0, len(s["data"]["name"]), len_upperbound)]

            if len(split_text) >= len(split_name):
                for l in range(0, len(split_text)):
                    output += split_text[l] + " " * (max_text_len - len(split_text[l]) + column_space)
                    if l < len(split_name):
                        output += split_name[l] + "\n"
                    else:
                        output += "\n"
            else:
                for l in range(0, len(split_name)):
                    if l < len(split_text):
                        output += split_text[l] + " " * (max_text_len - len(split_text[l]) + column_space)
                    else:
                        output += " " * (max_text_len + column_space)

                    output += split_name[l] + "\n"
        else:
            output += s["text"] + " " * (max_text_len - len(s["text"]) + column_space) + s["data"]["name"] + "\n"

    tab_name = fi.get_new_document_name("Identified strings")
    fi.newDocument(tab_name, 0)
    fi.setDocument(output)

    print('Identified strings are shown in the new "%s" tab.' % tab_name)
