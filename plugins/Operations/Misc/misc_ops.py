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
import os
import re
import subprocess
import tempfile
import time

def hash_values(fi):
    """
    Calculate hash values of CRC32, MD5, SHA1, SHA256, ssdeep, TLSH, imphash,
    impfuzzy, exphash, Rich PE header hash, authentihash, icon MD5, icon dhash,
    and telfhash of selected region (the whole file if not selected)
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
    p = subprocess.Popen([fi.get_embed_python(), "Misc/hash_values.py"], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # Receive hash values
    stdout_data_hash_values, stderr_data_hash_values = p.communicate(input=data)
    ret = p.wait()

    # There is a missing module
    if ret == -1:
        fi.show_module_install_instruction("magic", "python-magic-bin")
        return
    elif ret == -2:
        fi.show_module_install_instruction("pefile")
        return
    elif ret == -3:
        fi.show_module_install_instruction("pyimpfuzzy", "pyimpfuzzy-windows")
        return
    elif ret == -4:
        fi.show_module_install_instruction("tlsh", "py-tlsh")
        return
    elif ret == -5:
        fi.show_module_install_instruction("telfhash")
        return
    elif ret == -6:
        fi.show_module_install_instruction("LIEF", "lief")
        return
    elif ret == -7:
        fi.show_module_install_instruction("PIL", "Pillow")
        return
    else:
        if not os.path.exists("Misc/c_gimphash_windows.exe"):
            print("c_gimphash_windows.exe is not installed.")
            print("Please download it from https://github.com/NextronSystems/gimphash/releases")
            print("and place it into '%s' folder." % (os.getcwd() + "\\Misc"))
            return

        # Create a temporary file
        fd, filepath = tempfile.mkstemp()
        handle = os.fdopen(fd, "wb")
        handle.write(data)
        handle.close()

        # Execute c_gimphash_windows.exe for gimphash computation
        p = subprocess.Popen(["Misc/c_gimphash_windows.exe", filepath], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # Receive scan result
        stdout_data_gimphash, stderr_data_gimphash = p.communicate()
        ret = p.wait()

        if stdout_data_gimphash != "":
            gimphash = stdout_data_gimphash.split()[0]
            stdout_data_hash_values += "gimphash: %s\n" % gimphash

        os.remove(filepath) # Cleanup

        print(stdout_data_hash_values),
        print(stderr_data_hash_values),

def send_to_cli(fi):
    """
    Send selected region (the whole file if not selected) to other CLI program and get output
    """
    if fi.getDocumentCount() == 0:
        print("Please open a file to use this plugin.")
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
    p = subprocess.Popen([fi.get_embed_python(), "Misc/send_to_cli.py", filepath, str(point.x), str(point.y)], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout_data, stderr_data = p.communicate()
    ret = p.wait()

    # No external program is selected or "Customize menu" is selected
    if ret == 1:
        return

    if length > 0:
        if length == 1:
            print("Sent one byte from offset %s to %s to external program." % (hex(offset), hex(offset)))
        else:
            print("Sent %s bytes from offset %s to %s to external program." % (length, hex(offset), hex(offset + length - 1)))
    else:
        length = fi.getLength()
        if length == 1:
            print("Sent the whole file (one byte) to external program.")
        else:
            print("Sent the whole file (%s bytes) to external program." % length)

    if len(stdout_data) > 0:
        tab_name = fi.get_new_document_name("Output of Send to (CLI)")
        fi.newDocument(tab_name)
        fi.setDocument(stdout_data)

    print("Output of external program (stdout) is opened as new tab.")
    if stderr_data != "":
        print("Output of external program (stderr):")
        print(stderr_data)

def send_to_gui(fi):
    """
    Send selected region (the whole file if not selected) to other program.
    """
    if fi.getDocumentCount() == 0:
        print("Please open a file to use this plugin.")
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
    p = subprocess.Popen([fi.get_embed_python(), "Misc/send_to.py", filepath, str(point.x), str(point.y)], startupinfo=startupinfo)

    if length > 0:
        if length == 1:
            print("Sending one byte from offset %s to %s to external program." % (hex(offset), hex(offset)))
        else:
            print("Sending %s bytes from offset %s to %s to external program." % (length, hex(offset), hex(offset + length - 1)))
    else:
        length = fi.getLength()
        if length == 1:
            print("Sending the whole file (one byte) to external program.")
        else:
            print("Sending the whole file (%s bytes) to external program." % length)

def get_ssdeep(fi, data):
    """
    Get ssdeep hash value, used by file_comparison()
    """
    # Do not show command prompt window
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

    # Execute hash_values.py to get ssdeep hash value
    p = subprocess.Popen([fi.get_embed_python(), "Misc/hash_values.py", "ssdeep"], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # Receive hash value
    stdout_data, stderr_data = p.communicate(input=data)
    ret = p.wait()

    # There is a missing module
    if ret == -1:
        fi.show_module_install_instruction("magic", "python-magic-bin")
        return
    elif ret == -2:
        fi.show_module_install_instruction("pefile")
        return
    elif ret == -3:
        fi.show_module_install_instruction("pyimpfuzzy", "pyimpfuzzy-windows")
        return

    return stdout_data

def get_impfuzzy(fi, data):
    """
    Get impfuzzy hash value, used by file_comparison()
    """
    # Do not show command prompt window
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

    # Execute hash_values.py to get impfuzzy hash value
    p = subprocess.Popen([fi.get_embed_python(), "Misc/hash_values.py", "impfuzzy"], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # Receive hash value
    stdout_data, stderr_data = p.communicate(input=data)
    ret = p.wait()

    # There is a missing module
    if ret == -1:
        fi.show_module_install_instruction("magic", "python-magic-bin")
        return
    elif ret == -2:
        fi.show_module_install_instruction("pefile")
        return
    elif ret == -3:
        fi.show_module_install_instruction("pyimpfuzzy", "pyimpfuzzy-windows")
        return

    return stdout_data

def get_tlsh(fi, data):
    """
    Get TLSH value, used by file_comparison()
    """
    # Do not show command prompt window
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

    # Execute hash_values.py to get TLSH value
    p = subprocess.Popen([fi.get_embed_python(), "Misc/hash_values.py", "tlsh"], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # Receive hash value
    stdout_data, stderr_data = p.communicate(input=data)
    ret = p.wait()

    # There is a missing module
    if ret == -4:
        fi.show_module_install_instruction("tlsh", "py-tlsh")
        return

    return stdout_data

def compare_fuzzyhash(fi, hash1, hash2):
    """
    Compare fuzzy hash values, used by file_comparison()
    """
    # Do not show command prompt window
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

    # Execute hash_values.py to compare fuzzy hash values
    p = subprocess.Popen([fi.get_embed_python(), "Misc/hash_values.py", "compare-fuzzy", hash1, hash2], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # Receive hash value
    stdout_data, stderr_data = p.communicate()
    ret = p.wait()

    # There is a missing module
    if ret == -1:
        fi.show_module_install_instruction("magic", "python-magic-bin")
        return
    elif ret == -2:
        fi.show_module_install_instruction("pefile")
        return
    elif ret == -3:
        fi.show_module_install_instruction("pyimpfuzzy", "pyimpfuzzy-windows")
        return

    return stdout_data

def compare_tlsh(fi, hash1, hash2):
    """
    Compare TLSH values, used by file_comparison()
    """
    # Do not show command prompt window
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

    # Execute hash_values.py to compare TLSH values
    p = subprocess.Popen([fi.get_embed_python(), "Misc/hash_values.py", "compare-tlsh", hash1, hash2], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # Receive hash value
    stdout_data, stderr_data = p.communicate()
    ret = p.wait()

    # There is a missing module
    if ret == -4:
        fi.show_module_install_instruction("tlsh", "py-tlsh")
        return

    return stdout_data

def file_comparison(fi):
    """
    Compare contents of two files
    """
    num_file = fi.getDocumentCount()
    if num_file < 2:
        print("Please open at least two file to use this plugin.")
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

    # Execute file_comparison_dialog.py to show GUI
    p = subprocess.Popen([fi.get_embed_python(), "Misc/file_comparison_dialog.py"], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE)

    stdout_data, stderr_data = p.communicate(input=file_list)
    if stdout_data == "":
        fi.activateDocumentAt(current_file_index)
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

    if len(bookmark_list) > 100 and not fi.bookmark_yesno_dialog(len(bookmark_list)):
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

        ssdeep_first = get_ssdeep(fi, first_data)
        ssdeep_second = get_ssdeep(fi, second_data)

        if ssdeep_first != "" and ssdeep_second != "":
            print("ssdeep hash of %s:\t%s" % (first_name, ssdeep_first))
            print("ssdeep hash of %s:\t%s" % (second_name, ssdeep_second))
            print("ssdeep hash comparison score (0-100, higher score means more similar): %s" % compare_fuzzyhash(fi, ssdeep_first, ssdeep_second))
            print("")

        tlsh_first = get_tlsh(fi, first_data)
        if tlsh_first == "TNULL":
            tlsh_first += " (the file size is less than the minimum size (50 bytes))"
        tlsh_second = get_tlsh(fi, second_data)
        if tlsh_second == "TNULL":
            tlsh_second += " (the file size is less than the minimum size (50 bytes))"

        if tlsh_first != "" and tlsh_second != "":
            print("TLSH of %s:\t%s" % (first_name, tlsh_first))
            print("TLSH of %s:\t%s" % (second_name, tlsh_second))
            print("TLSH comparison score (lower score means more similar): %s" % compare_tlsh(fi, tlsh_first, tlsh_second))
            print("")

        if first_data[:2] == "MZ":
            impfuzzy_first = get_impfuzzy(fi, first_data)
        else:
            impfuzzy_first = ""

        if second_data[:2] == "MZ":
            impfuzzy_second = get_impfuzzy(fi, second_data)
        else:
            impfuzzy_second = ""

        if impfuzzy_first != "" and impfuzzy_second != "":
            print("impfuzzy hash of %s:\t%s" % (first_name, impfuzzy_first))
            print("impfuzzy hash of %s:\t%s" % (second_name, impfuzzy_second))
            print("impfuzzy hash comparison score (0-100, higher score means more similar): %s" % compare_fuzzyhash(fi, impfuzzy_first, impfuzzy_second))
            print("")

    print("Elapsed time: %f (sec)" % (time.time() - time_start))

def emulate_code(fi):
    """
    Emulate selected region as an executable or shellcode with Qiling Framework (the whole file if not selected)
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

    # Execute emulate_shellcode_dialog.py to show GUI
    p = subprocess.Popen([fi.get_embed_python(), "Misc/emulate_code_dialog.py"], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    stdout_data, stderr_data = p.communicate()
    if stdout_data == "":
        return

    # Get parameters from emulate_code_dialog.py
    (framework, file_type, os_type, arch, big_endian, cmd_args, multithread, timeout, rootfs_path) = stdout_data.split("\t")

    # Create a temporary file to write data
    if rootfs_path != "None":
        fd, file_path = tempfile.mkstemp(dir=rootfs_path) # For Qiling Framework, a temporary file is created under rootfs directory
    else:
        fd, file_path = tempfile.mkstemp()
    handle = os.fdopen(fd, "wb")
    handle.write(data)
    handle.close()

    tab_name = fi.get_new_document_name("Emulation trace")
    tab_index = tab_name[16:] # Get index number

    # Execute emulate_code_qiling.py or emulate_code_speakeasy.py to emulate code
    if framework == "Qiling Framework":
        p = subprocess.Popen([fi.get_embed_python(), "Misc/emulate_code_qiling.py", file_path, file_type, os_type, arch, big_endian, cmd_args, multithread, timeout, tab_index], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    else: # Speakeasy
        p = subprocess.Popen([fi.get_embed_python(), "Misc/emulate_code_speakeasy.py", file_path, file_type, os_type, arch, cmd_args, timeout, tab_index], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # Receive scan result
    stdout_data, stderr_data = p.communicate()
    ret = p.wait()

    os.remove(file_path) # Cleanup temporary file

    # emulate_code_qiling.py exited with error
    if ret == 1:
        stderr_data = stderr_data.replace("\x0d\x0a", "\x0a")
        # Remove colorlized part of log data introduced since Qiling Framework 1.2.1
        stderr_data = re.sub("\[\x1b\[\d{2}m.\x1b\[0m\] \[.+\.py:\d+\]\t", "", stderr_data)
        stderr_data = re.sub("\x1b\[\d{2}m", "", stderr_data)
        stderr_data = re.sub("\x1b\[0m", "", stderr_data)
        print(stderr_data),
        return
    elif ret < 0:
        if ret == -1: # packaging is not installed
            fi.show_module_install_instruction("packaging")

        if ret == -2: # Qiling Framework is not installed
            fi.show_module_install_instruction("Qiling Framework", "qiling")

        if ret == -3: # watchdog is not installed
            fi.show_module_install_instruction("watchdog")

        if ret == -4: # rootfs files are not installed
            print(stderr_data)
            print("Rootfs files of Qiling Framework are not properly installed.")
            print("Please download them from https://github.com/qilingframework/qiling/archive/master.zip")
            print("and copy extracted 'qiling-master' folder into '%s' folder." % (os.getcwd() + "\\Misc"))
            print("Then please download them from https://github.com/qilingframework/rootfs/archive/master.zip")
            print("and copy extracted folders such as 'arm_linux' under 'rootfs-master' folder into '%s' folder." % (os.getcwd() + "\\Misc\\qiling-master\\examples\\rootfs"))
            print("")
            print("After them please setup ntoskrnl.exe, DLL files and registry files of rootfs with the following command on PowerShell:")
            print("Start-Process powershell -Verb RunAs -Wait -ArgumentList \"-Command `\"cd '%s\qiling-master'; examples\scripts\dllscollector.bat`\"\"" % (os.getcwd() + "\\Misc"))
            print("")
            print("You can also do the setup with install.ps1:")
            print("powershell -exec bypass -command \"IEX((New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/nmantani/FileInsight-plugins/master/install.ps1'))\"")

        if ret == -5: # Speakeasy is not installed
            fi.show_module_install_instruction("speakeasy", "speakeasy-emulator")

        return

    if fi.getSelectionLength() > 0:
        print("Emulated from offset %s to %s as %s.\n" % (hex(offset), hex(offset + length), file_type.lower()))
    else:
        print("Emulated the whole file as %s.\n" % file_type.lower())

    print("Emulation settings:")
    print("Emulation framework: %s" % framework)
    print("File type: %s" % file_type.lower())
    print("OS: %s" % os_type)
    print("Architecture: %s" % arch)
    if framework == "Qiling Framework":
        print("Big endian: %s" % str(big_endian).lower())
    print("Command line arguments: %s" % cmd_args)
    if framework == "Qiling Framework":
        print("Multithread: %s" % str(multithread))
    print("Timeout: %s" % timeout)
    print("")

    trace = "Emulation trace:\n"
    stderr_data = stderr_data.replace("\x0d\x0a", "\x0a")
    # Remove colorlized part of log data introduced since Qiling Framework 1.2.1
    stderr_data = re.sub("\[\x1b\[\d{2}m.\x1b\[0m\] \[.+\.py:\d+\]\t", "", stderr_data)
    stderr_data = re.sub("\x1b\[\d{2}m", "", stderr_data)
    stderr_data = re.sub("\x1b\[0m", "", stderr_data)
    stderr_data = re.sub("\[=\]\t\[\+\] ", "", stderr_data)
    trace += stderr_data

    # For the case that emulate_code_qiling.py exited during ql.run()
    if stdout_data == "":
        print("Emulation aborted.")
        return

    # Get current number of opened tabs
    num_tabs = fi.getDocumentCount()

    # Split stdout_data into stdout_written that is written by emulated code and memory dumps
    stdout_splitted = stdout_data.split("****MEMDUMP****")
    stdout_written = stdout_splitted[0]
    if stdout_written != "":
        trace += "Output of the emulated code:\n"
        trace += stdout_written

    tab_name = fi.get_new_document_name("Emulation trace")
    fi.newDocument(tab_name, 0)
    fi.setDocument(trace)

    if len(stdout_splitted) > 1:
        bookmarked = False
        #tab_name = fi.get_new_document_name("Memory dump")
        for i in range(1, len(stdout_splitted)):
            memory_dump = stdout_splitted[i]
            fi.newDocument("Memory dump %s - %d" % (tab_index, (i - 1)), 1)
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
            print("Added bookmarks to the region of the memory dumps that contain non-zero value.")

    print('Emulation trace is shown in the new "Emulation trace %s" tab.' % tab_index)
    print('Memory dumps after execution are shown in the new "Memory dump %s - *" tabs.' % tab_index)

    # Set current tab to "Emulation trace" tab
    fi.activateDocumentAt(num_tabs)
