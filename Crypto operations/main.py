#
# Crypto operations - Various cryptographic operations
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
import subprocess
import crypto_ops

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
        self.getDocument = getDocument
        self.getDocumentName = getDocumentName
        self.getDocumentCount = getDocumentCount
        self.getDocumentURL = getDocumentURL
        self.activateDocumentAt = activateDocumentAt

if __name__ == "__main__":
    operations = (crypto_ops.aes_decrypt,
                  crypto_ops.aes_encrypt,
                  crypto_ops.arc4_decrypt,
                  crypto_ops.blowfish_decrypt,
                  crypto_ops.blowfish_encrypt,
                  crypto_ops.des_decrypt,
                  crypto_ops.des_encrypt,
                  crypto_ops.triple_des_decrypt,
                  crypto_ops.triple_des_encrypt)

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

    # Execute menu.py to show GUI
    # GUI portion is moved to menu.py to avoid hangup of FileInsight
    p = subprocess.Popen(["python", "menu.py", str(point.x), str(point.y)], startupinfo=startupinfo)
    index = p.wait() # Receive exit value as index of selected plugin

    if index >= 0:
        fi = FileInsight()
        operations[index](fi)

