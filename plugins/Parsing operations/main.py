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

import ctypes
import os
import re
import subprocess
import parsing_ops

class FileInsight:
    """
    Class for FileInsight built-in functions
    """
    def __init__(self):
        self.getLength = getLength
        self.getByteAt = getByteAt
        self.setByteAt = setByteAt
        self.setBookmark = setBookmark
        self.getSelection = getSelection
        self.getSelectionOffset = getSelectionOffset
        self.getSelectionLength = getSelectionLength
        self.gotoBookmark = gotoBookmark
        self.download = download
        self.newDocument = newDocument
        self.showSimpleDialog = showSimpleDialog
        self.decode = decode
        self.setDocument = setDocument
        self.getDocumentName = getDocumentName
        self.getDocumentCount = getDocumentCount
        self.getDocumentURL = getDocumentURL
        self.activateDocumentAt = activateDocumentAt

    # Workaround for the truncation bug of getDocument()
    def getDocument(self):
        length = getLength()
        data = getDocument()
        if length - len(data) > 0:
            for i in range(len(data), length):
                data += getByteAt(i)

        return data

def find_python3():
    pyexe_found = False
    if os.path.exists("C:/Windows/py.exe") or os.path.exists(os.environ["LOCALAPPDATA"].replace("\\", "/") + "/Programs/Python/Launcher/py.exe"):
        pyexe_found = True
    
    if not pyexe_found:
        print("Error: py.exe is not found. You need to install Python 3 to use FileInsight-plugins.")

    python3_version = ["30", "31", "33", "34", "35", "36", "37", "38", "39"]
    python3_found = False
    for v in python3_version:
        if os.path.exists("C:/Program Files/Python%s/python.exe" % v) \
           or os.path.exists("C:/Program Files (x86)/Python%s-32/python.exe" % v) \
           or os.path.exists(os.environ["LOCALAPPDATA"].replace("\\", "/") + "/Programs/Python/Python%s/python.exe" % v) \
           or os.path.exists(os.environ["LOCALAPPDATA"].replace("\\", "/") + "/Programs/Python/Python%s-32/python.exe" % v):
           python3_found = True
           break
    
    if not python3_found:
       print("Error: python.exe is not found. You need to install Python 3 to use FileInsight-plugins.")

    return pyexe_found and python3_found

if __name__ == "__main__":
    operations = (parsing_ops.binwalk_scan,
                  parsing_ops.file_type,
                  parsing_ops.find_pe_file,
                  parsing_ops.show_metadata,
                  parsing_ops.strings)

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

    # Do not show command prompt window
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

    if find_python3():
        # Execute menu.py to show GUI
        # GUI portion is moved to menu.py to avoid hangup of FileInsight
        p = subprocess.Popen(["py.exe", "-3", "menu.py", str(point.x), str(point.y)], startupinfo=startupinfo)
        index = p.wait() # Receive exit value as index of selected plugin

        if index >= 0:
            fi = FileInsight()
            operations[index](fi)

    # Workaround to avoid crash of FileInsight on Windows 7
    if "threading" in sys.modules:
        sys.modules.pop("threading")
