#
# Send to - Send selected region (the whole file if not selected) to other programs
#
# Copyright (c) 2014-2018, Nobutaka Mantani
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


# TO CUSTOMIZE MENU ITEMS, PLEASE EDIT "PROGRAMS" VARIABLE IN LAUNCHER.PY.

import ctypes
import tempfile
import subprocess
import os

# Structure for mouse cursor position
class _point_t(ctypes.Structure):
    _fields_ = [
                ('x',  ctypes.c_long),
                ('y',  ctypes.c_long),
               ]

offset = getSelectionOffset()
length = getSelectionLength()
if (length > 0):
    data = getSelection()
else:
    data = getDocument()

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

# Execute launcher.py to show GUI
# GUI portion is moved to launcher.py to avoid hangup of FileInsight
p = subprocess.Popen(["python", "launcher.py", filepath, str(point.x), str(point.y)], startupinfo=startupinfo)

if (length > 0):
    if (length == 1):
        print "Sending one byte from offset %s to %s to an external program." % (hex(offset), hex(offset))
    else:
        print "Sending %s bytes from offset %s to %s to an external program." % (length, hex(offset), hex(offset + length - 1))
else:
    length = getLength()
    if (length == 1):
        print "Sending the whole file (one byte) to an external program."
    else:
        print "Sending the whole file (%s bytes) to an external program." % length

