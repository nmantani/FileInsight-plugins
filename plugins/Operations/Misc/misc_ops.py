#
# Misc operations - Miscellaneous operations
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
import hashlib
import os
import re
import sys
import subprocess
import tempfile
import time
import zlib

def bookmark_yesno_dialog(num_bookmark):
    """
    Show a confirmation dialog of adding many bookmarks
    Used by file_comparison()
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

def byte_frequency(fi):
    """
    Show byte frequency of selected region (the whole file if not selected)
    """
    length = fi.getSelectionLength()
    offset = fi.getSelectionOffset()

    if length > 0:
        buf = fi.getSelection()
        print("Byte frequency from offset %s to %s" % (hex(offset), hex(offset + length - 1)))
    else:
        buf = fi.getDocument()
        length = fi.getLength()
        print("Byte frequency of the whole file")

    freq = {}

    for i in range(0, 256):
        freq[i] = 0

    for i in range(0, length):
        v = ord(buf[i])
        if v in freq:
            freq[v] += 1

    output = ""
    for k, v in sorted(freq.items(), key=lambda x:x[1], reverse=True):
        output += "0x%02X: %d\n" % (k, v)
    print(output)

def hash_values(fi):
    """
    Calculate MD5, SHA1, SHA256 hash values of selected region (the whole file if not selected)
    """
    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()
    if length > 0:
        data = fi.getSelection()
        print("Hash values from offset %s to %s" % (hex(offset), hex(offset + length - 1)))
    else:
        data = fi.getDocument()
        print("Hash values of the whole file")

    print("CRC32: %x" % (zlib.crc32(data) & 0xffffffff))
    print("MD5: %s" % hashlib.md5(data).hexdigest())
    print("SHA1: %s" % hashlib.sha1(data).hexdigest())
    print("SHA256: %s" % hashlib.sha256(data).hexdigest())

def send_to(fi):
    """
    Send selected region (the whole file if not selected) to other programs.
    TO CUSTOMIZE MENU ITEMS, PLEASE EDIT "PROGRAMS" VARIABLE IN SEND_TO.PY.
    """
    if fi.getDocumentCount() == 0:
        return

    # Structure for mouse cursor position
    class _point_t(ctypes.Structure):
        _fields_ = [
                    ('x',  ctypes.c_long),
                    ('y',  ctypes.c_long),
                    ]

    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    if length > 0:
        data = fi.getSelection()
    else:
        data = fi.getDocument()

    # Create a temporary file
    fd, filepath = tempfile.mkstemp()
    handle = os.fdopen(fd, "w")
    handle.write(data)
    handle.close()

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

    # Do not show command prompt window
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

    # Execute send_to.py to show GUI
    # GUI portion is moved to send_to.py to avoid hangup of FileInsight
    p = subprocess.Popen(["py.exe", "-3", "Misc/send_to.py", filepath, str(point.x), str(point.y)], startupinfo=startupinfo)

    if length > 0:
        if length == 1:
            print("Sending one byte from offset %s to %s to an external program." % (hex(offset), hex(offset)))
        else:
            print("Sending %s bytes from offset %s to %s to an external program." % (length, hex(offset), hex(offset + length - 1)))
    else:
        length = fi.getLength()
        if length == 1:
            print("Sending the whole file (one byte) to an external program.")
        else:
            print("Sending the whole file (%s bytes) to an external program." % length)

def file_comparison(fi):
    """
    Compare contents of two files
    """
    cp = ctypes.windll.kernel32.GetACP()
    cp = "cp%d" % cp

    num_file = fi.getDocumentCount()
    if num_file < 2:
        return

    file_list = ""
    for i in range(num_file):
        fi.activateDocumentAt(i)
        file_list += "%s\r\n" % fi.getDocumentName().decode(cp).encode("utf-8")

    # Do not show command prompt window
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

    # Execute file_comparison_dialog.py to show GUI
    p = subprocess.Popen(["py.exe", "-3", "Misc/file_comparison_dialog.py"], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE)

    stdout_data, stderr_data = p.communicate(input=file_list)
    if stdout_data == "":
        return
    (first_index, second_index) = stdout_data.split()

    time_start = time.time()

    fi.activateDocumentAt(int(first_index))
    first_data = list(fi.getDocument())
    first_len = fi.getLength()
    fi.activateDocumentAt(int(second_index))
    second_data = list(fi.getDocument())
    second_len = fi.getLength()

    if first_len < second_len:
        lower_len = first_len
        upper_len = second_len
    elif first_len > second_len:
        lower_len = second_len
        upper_len = first_len
    else:
        lower_len = first_len
        upper_len = first_len

    bookmark_list = []
    offset = None
    for i in range(lower_len):
        if first_data[i] != second_data[i] and offset == None:
            offset = i
        elif first_data[i] == second_data[i] and offset != None:
            bookmark_list.append((offset, i - offset))
            offset = None

    if offset != None:
        bookmark_list.append((offset, i - offset + 1))
        offset = None

    if len(bookmark_list) > 100 and not bookmark_yesno_dialog(len(bookmark_list)):
        do_bookmark = False
    else:
        do_bookmark = True

    if lower_len == upper_len and len(bookmark_list) == 0:
        print("Both files are identical.")
        return
    else:
        print("Delta:")
        output = ""
        fi.activateDocumentAt(int(first_index))
        for (i, j) in bookmark_list:
            if do_bookmark: fi.setBookmark(i, j, hex(i), "#ffaad4")
            output += "Offset: %s - %s\n" % (hex(i), hex(i + j - 1))

        fi.activateDocumentAt(int(second_index))
        for (i, j) in bookmark_list:
            if do_bookmark: fi.setBookmark(i, j, hex(i), "#ffaad4")
            output += "Offset: %s - %s\n" % (hex(i), hex(i + j - 1))

        if lower_len != upper_len:
            if first_len > second_len:
                fi.activateDocumentAt(int(first_index))
            else:
                fi.activateDocumentAt(int(second_index))
            if do_bookmark: fi.setBookmark(lower_len, upper_len - lower_len, hex(lower_len), "#ffaad4")
            output += "Offset: %s - %s\n" % (hex(lower_len), hex(upper_len - 1))

        fi.activateDocumentAt(int(first_index))
        print(output)
        print("Added bookmarks to the deltas.")

    print("Elapsed time: %f (sec)" % (time.time() - time_start))

def emulate_code(fi):
    """
    Emulate selected region as an executable or shellcode with Qiling Framework (the whole file if not selected)
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

    # Execute emulate_shellcode_dialog.py to show GUI
    p = subprocess.Popen(["py.exe", "-3", "Misc/emulate_code_dialog.py"], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE)

    stdout_data, stderr_data = p.communicate()
    if stdout_data == "":
        return

    # Get parameters from emulate_code_dialog.py
    (file_type, os_type, arch, big_endian, cmd_args) = stdout_data.split("\t")

    # Create a temporary file to write data
    fd, file_path = tempfile.mkstemp()
    handle = os.fdopen(fd, "wb")
    handle.write(data)
    handle.close()

    # Execute emulate_code.py to emulate code
    p = subprocess.Popen(["py.exe", "-3", "Misc/emulate_code.py", file_path, file_type, os_type, arch, big_endian, cmd_args], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # Receive scan result
    stdout_data, stderr_data = p.communicate()
    ret = p.wait()

    os.remove(file_path) # Cleanup temporary file

    # emulate_code.py exited with error
    if ret == 1:
        print(stderr_data.replace("\x0d\x0a", "\x0a")),
        return
    elif ret == -1 or ret == -2:
        if ret == -1: # Qiling Framework is not installed
            print("Qiling Framework is not installed.")
            print("Please install it with 'py.exe -3 -m pip install qiling'.")
            print("")

        if ret == -2: # rootfs files are not installed
            print("Rootfs files of Qiling Framework are not installed.")
            print("Please download them from https://github.com/qilingframework/qiling/archive/master.zip")
            print("and copy extracted 'qiling-master' folder into '%s' folder." % (os.getcwd() + "\\Misc"))
            print("")
            print("Then please setup DLL files and registry files of rootfs with the following command on PowerShell:")
            print("Start-Process powershell -Verb RunAs -Wait -ArgumentList \"-Command `\"cd '%s\qiling-master'; examples\scripts\dllscollector.bat`\"\"" % (os.getcwd() + "\\Misc"))
            print("")

        print("You can also do the setup with install.ps1:")
        print("powershell -exec bypass -command \"IEX((New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/nmantani/FileInsight-plugins/master/install.ps1'))\"")
        return

    if fi.getSelectionLength() > 0:
        print("Emulated from offset %s to %s as %s.\n" % (file_type.lower(), hex(offset), hex(offset + length)))
    else:
        print("Emulated the whole file as %s.\n" % file_type.lower())

    print("Emulation setting:")
    print("File type: %s" % file_type.lower())
    print("OS: %s" % os_type)
    print("Architecture: %s" % arch)
    print("Big endian: %s" % str(big_endian).lower())
    print("Command line arguments: %s" % cmd_args)

    print("Emulation trace:")
    print(stderr_data.replace("\x0d\x0a", "\x0a")),

    # For the case that emulate_code.py exited during ql.run()
    if stdout_data == "":
        print("Emulation aborted.")
        return

    # Split stdout_data into stdout_written that is written by emulated code and memory dumps
    stdout_splitted = stdout_data.split("****MEMDUMP****")
    stdout_written = stdout_splitted[0]
    print("Output of the emulated code:")
    print(stdout_written)

    if len(stdout_splitted) > 1:
        bookmarked = False
        for i in range(1, len(stdout_splitted)):
            memory_dump = binascii.a2b_hex(stdout_splitted[i])
            fi.newDocument("Memory dump %d" % (i - 1), 1)
            fi.setDocument("".join(memory_dump))

            start = None
            num_zero = 0
            for j in range(0, len(memory_dump)):
                if memory_dump[j] == b"\x00":
                    if start != None:
                        num_zero += 1
                else:
                    if start == None:
                        start = j
                    last_nonzero = j
                    num_zero = 0

                # Split bookmark regions if there is continuous zeros more than 1024 bytes
                if start != None and num_zero > 1024:
                    fi.setBookmark(start, last_nonzero - start + 1, hex(start), "#c8ffff")
                    start = None
                    num_zero = 0

            if start != None:
                fi.setBookmark(start, last_nonzero - start + 1, hex(start), "#c8ffff")
                bookmarked = True

        if bookmarked == True:
            print("Added bookmarks to the region that contains non-zero value.")

    print('Memory dumps after execution are shown in the new "Memory dump" tabs.')
