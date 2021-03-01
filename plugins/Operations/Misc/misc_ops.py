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
        data = fi.getSelection()
        print("Byte frequency from offset %s to %s" % (hex(offset), hex(offset + length - 1)))
    else:
        data = fi.getDocument()
        length = fi.getLength()
        print("Byte frequency of the whole file")

    freq = {}

    for i in range(0, 256):
        freq[i] = 0

    for i in range(0, length):
        v = ord(data[i])
        if v in freq:
            freq[v] += 1

    output = ""
    for k, v in sorted(freq.items(), key=lambda x:x[1], reverse=True):
        output += "0x%02X: %d\n" % (k, v)
    print(output)

def hash_values(fi):
    """
    Calculate MD5, SHA1, SHA256, ssdeep, imphash, impfuzzy hash values of selected region (the whole file if not selected)
    """
    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()
    if length > 0:
        data = fi.getSelection()
        print("Hash values from offset %s to %s:" % (hex(offset), hex(offset + length - 1)))
    else:
        data = fi.getDocument()
        print("Hash values of the whole file:")

    # Do not show command prompt window
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

    # Execute hash_values.py to get hash values
    p = subprocess.Popen(["py.exe", "-3", "Misc/hash_values.py"], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # Receive hash values
    stdout_data, stderr_data = p.communicate(input=data)
    ret = p.wait()

    # There is a missing module
    if ret == -1:
        print("python-magic is not installed.")
        print("Please install it with 'py.exe -3 -m pip install python-magic-bin' and try again.")
        print("")
        return
    elif ret == -2:
        print("pefile is not installed.")
        print("Please install it with 'py.exe -3 -m pip install pefile' and try again.")
        print("")
        return
    elif ret == -3:
        print("pyimpfuzzy-windows is not installed.")
        print("Please install it with 'py.exe -3 -m pip install pyimpfuzzy-windows' and try again.")
        print("")
        return
    else:
        print(stdout_data),
        print(stderr_data),

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

def get_ssdeep(data):
    """
    Get ssdeep hash value, used by file_comparison()
    """
    # Do not show command prompt window
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

    # Execute hash_values.py to get ssdeep hash value
    p = subprocess.Popen(["py.exe", "-3", "Misc/hash_values.py", "ssdeep"], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # Receive hash value
    stdout_data, stderr_data = p.communicate(input=data)
    ret = p.wait()

    # There is a missing module
    if ret == -1:
        print("python-magic is not installed.")
        print("Please install it with 'py.exe -3 -m pip install python-magic-bin' and try again.")
        print("")
        return
    elif ret == -2:
        print("pefile is not installed.")
        print("Please install it with 'py.exe -3 -m pip install pefile' and try again.")
        print("")
        return
    elif ret == -3:
        print("pyimpfuzzy-windows is not installed.")
        print("Please install it with 'py.exe -3 -m pip install pyimpfuzzy-windows' and try again.")
        print("")
        return

    return stdout_data

def get_impfuzzy(data):
    """
    Get impfuzzy hash value, used by file_comparison()
    """
    # Do not show command prompt window
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

    # Execute hash_values.py to get impfuzzy hash value
    p = subprocess.Popen(["py.exe", "-3", "Misc/hash_values.py", "impfuzzy"], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # Receive hash value
    stdout_data, stderr_data = p.communicate(input=data)
    ret = p.wait()

    # There is a missing module
    if ret == -1:
        print("python-magic is not installed.")
        print("Please install it with 'py.exe -3 -m pip install python-magic-bin' and try again.")
        print("")
        return
    elif ret == -2:
        print("pefile is not installed.")
        print("Please install it with 'py.exe -3 -m pip install pefile' and try again.")
        print("")
        return
    elif ret == -3:
        print("pyimpfuzzy-windows is not installed.")
        print("Please install it with 'py.exe -3 -m pip install pyimpfuzzy-windows' and try again.")
        print("")
        return

    return stdout_data

def compare_hash(hash1, hash2):
    """
    Compare hash value,s used by file_comparison()
    """
    # Do not show command prompt window
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

    # Execute hash_values.py to get impfuzzy hash value
    p = subprocess.Popen(["py.exe", "-3", "Misc/hash_values.py", "compare", hash1, hash2], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # Receive hash value
    stdout_data, stderr_data = p.communicate()
    ret = p.wait()

    # There is a missing module
    if ret == -1:
        print("python-magic is not installed.")
        print("Please install it with 'py.exe -3 -m pip install python-magic-bin' and try again.")
        print("")
        return
    elif ret == -2:
        print("pefile is not installed.")
        print("Please install it with 'py.exe -3 -m pip install pefile' and try again.")
        print("")
        return
    elif ret == -3:
        print("pyimpfuzzy-windows is not installed.")
        print("Please install it with 'py.exe -3 -m pip install pyimpfuzzy-windows' and try again.")
        print("")
        return

    return stdout_data

def file_comparison(fi):
    """
    Compare contents of two files
    """
    num_file = fi.getDocumentCount()
    if num_file < 2:
        return

    file_list = ""
    for i in range(num_file):
        fi.activateDocumentAt(i)
        file_list += "%s\r\n" % fi.getDocumentName()

    # Do not show command prompt window
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

    # Execute file_comparison_dialog.py to show GUI
    p = subprocess.Popen(["py.exe", "-3", "Misc/file_comparison_dialog.py"], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE)

    stdout_data, stderr_data = p.communicate(input=file_list)
    if stdout_data == "":
        return
    (first_index, second_index) = stdout_data.split()

    first_index = int(first_index)
    second_index = int(second_index)

    time_start = time.time()

    fi.activateDocumentAt(first_index)
    first_name = fi.getDocumentName()
    first_data = list(fi.getDocument())
    first_len = fi.getLength()

    fi.activateDocumentAt(second_index)
    second_name = fi.getDocumentName()
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
        fi.activateDocumentAt(first_index)
        for (i, j) in bookmark_list:
            if do_bookmark: fi.setBookmark(i, j, hex(i), "#ffaad4")
            output += "Offset: %s - %s\n" % (hex(i), hex(i + j - 1))

        fi.activateDocumentAt(second_index)
        for (i, j) in bookmark_list:
            if do_bookmark: fi.setBookmark(i, j, hex(i), "#ffaad4")

        if lower_len != upper_len:
            if first_len > second_len:
                fi.activateDocumentAt(first_index)
            else:
                fi.activateDocumentAt(second_index)
            if do_bookmark: fi.setBookmark(lower_len, upper_len - lower_len, hex(lower_len), "#ffaad4")
            output += "Offset: %s - %s\n" % (hex(lower_len), hex(upper_len - 1))

        fi.activateDocumentAt(first_index)
        print(output)
        print("Added bookmarks to the deltas.")
        print("")

        first_data = "".join(first_data)
        second_data = "".join(second_data)

        ssdeep_first = get_ssdeep(first_data)
        ssdeep_second = get_ssdeep(second_data)

        if ssdeep_first != "" and ssdeep_second != "":
            print("ssdeep hash of %s:\t%s" % (first_name, ssdeep_first))
            print("ssdeep hash of %s:\t%s" % (second_name, ssdeep_second))
            print("ssdeep hash comparison score (0-100): %s" % compare_hash(ssdeep_first, ssdeep_second))
            print("")

        if first_data[:2] == "MZ":
            impfuzzy_first = get_impfuzzy(first_data)
        else:
            impfuzzy_first = ""

        if second_data[:2] == "MZ":
            impfuzzy_second = get_impfuzzy(second_data)
        else:
            impfuzzy_second = ""

        if impfuzzy_first != "" and impfuzzy_second != "":
            print("impfuzzy hash of %s:\t%s" % (first_name, impfuzzy_first))
            print("impfuzzy hash of %s:\t%s" % (second_name, impfuzzy_second))
            print("impfuzzy hash comparison score (0-100): %s" % compare_hash(impfuzzy_first, impfuzzy_second))
            print("")

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
    (file_type, os_type, arch, big_endian, cmd_args, timeout) = stdout_data.split("\t")

    # Create a temporary file to write data
    fd, file_path = tempfile.mkstemp()
    handle = os.fdopen(fd, "wb")
    handle.write(data)
    handle.close()

    # Execute emulate_code.py to emulate code
    p = subprocess.Popen(["py.exe", "-3", "Misc/emulate_code.py", file_path, file_type, os_type, arch, big_endian, cmd_args, timeout], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # Receive scan result
    stdout_data, stderr_data = p.communicate()
    ret = p.wait()

    os.remove(file_path) # Cleanup temporary file

    # emulate_code.py exited with error
    if ret == 1:
        stderr_data = stderr_data.replace("\x0d\x0a", "\x0a")
        # Remove colorlized part of log data introduced since Qiling Framework 1.2.1
        stderr_data = re.sub("\[\x1b\[\d{2}m.\x1b\[0m\] \[.+\.py:\d+\]\t", "", stderr_data)
        stderr_data = re.sub("\x1b\[\d{2}m", "", stderr_data)
        stderr_data = re.sub("\x1b\[0m", "", stderr_data)
        print(stderr_data),
        return
    elif ret == -1 or ret == -2 or ret == -3:
        if ret == -1: # Qiling Framework is not installed
            print("Qiling Framework is not installed.")
            print("Please install it with 'py.exe -3 -m pip install qiling'.")
            print("")

        if ret == -2: # watchdog is not installed
            print("watchdog is not installed.")
            print("Please install it with 'py.exe -3 -m pip install watchdog'.")
            print("")

        if ret == -3: # rootfs files are not installed
            print(stderr_data)
            print("Rootfs files of Qiling Framework are not properly installed.")
            print("Please download them from https://github.com/qilingframework/qiling/archive/master.zip")
            print("and copy extracted 'qiling-master' folder into '%s' folder." % (os.getcwd() + "\\Misc"))
            print("")
            print("Then please setup ntoskrnl.exe, DLL files and registry files of rootfs with the following command on PowerShell:")
            print("Start-Process powershell -Verb RunAs -Wait -ArgumentList \"-Command `\"cd '%s\qiling-master'; examples\scripts\dllscollector.bat`\"\"" % (os.getcwd() + "\\Misc"))
            print("")
            print("You can also do the setup with install.ps1:")
            print("powershell -exec bypass -command \"IEX((New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/nmantani/FileInsight-plugins/master/install.ps1'))\"")

        return

    if fi.getSelectionLength() > 0:
        print("Emulated from offset %s to %s as %s.\n" % (hex(offset), hex(offset + length), file_type.lower()))
    else:
        print("Emulated the whole file as %s.\n" % file_type.lower())

    print("Emulation settings:")
    print("File type: %s" % file_type.lower())
    print("OS: %s" % os_type)
    print("Architecture: %s" % arch)
    print("Big endian: %s" % str(big_endian).lower())
    print("Command line arguments: %s" % cmd_args)
    print("Timeout: %s" % timeout)
    print("")

    print("Emulation trace:")
    stderr_data = stderr_data.replace("\x0d\x0a", "\x0a")
    # Remove colorlized part of log data introduced since Qiling Framework 1.2.1
    stderr_data = re.sub("\[\x1b\[\d{2}m.\x1b\[0m\] \[.+\.py:\d+\]\t", "", stderr_data)
    stderr_data = re.sub("\x1b\[\d{2}m", "", stderr_data)
    stderr_data = re.sub("\x1b\[0m", "", stderr_data)
    stderr_data = re.sub("\[=\]\t\[\+\] ", "", stderr_data)
    print(stderr_data),

    # For the case that emulate_code.py exited during ql.run()
    if stdout_data == "":
        print("Emulation aborted.")
        return

    # Split stdout_data into stdout_written that is written by emulated code and memory dumps
    stdout_splitted = stdout_data.split("****MEMDUMP****")
    stdout_written = stdout_splitted[0]
    if stdout_written != "":
        print("Output of the emulated code:")
        print(stdout_written)
        print("")

    if len(stdout_splitted) > 1:
        bookmarked = False
        for i in range(1, len(stdout_splitted)):
            memory_dump = stdout_splitted[i]
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
                    bookmarked = True

            if start != None:
                fi.setBookmark(start, last_nonzero - start + 1, hex(start), "#c8ffff")
                bookmarked = True

        if bookmarked == True:
            print("Added bookmarks to the region that contains non-zero value.")

    print('Memory dumps after execution are shown in the new "Memory dump" tabs.')

def bitmap_view(fi):
    """
    Visualize the whole file as bitmap representation
    """
    data = fi.getDocument()

    # Create a temporary file
    fd, filepath = tempfile.mkstemp()
    handle = os.fdopen(fd, "w")
    handle.write(data)
    handle.close()

    # Do not show command prompt window
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

    # Check existence of Pillow
    p = subprocess.Popen(["py.exe", "-3", "Misc/bitmap_view.py", "-c"], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    ret = p.wait()

    if ret == -1: # Pillow is not installed
        print("Pillow is not installed.")
        print("Please install it with 'py.exe -3 -m pip install Pillow'.")
        print("")
        return

    print("Sending the whole file to the viewer GUI.")
    print("You can move window by dragging bitmap image.")
    print("You can also copy current offset by right-clicking bitmap image.")

    # Execute bitmap_view.py to show GUI in background
    p = subprocess.Popen(["py.exe", "-3", "Misc/bitmap_view.py", filepath], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

