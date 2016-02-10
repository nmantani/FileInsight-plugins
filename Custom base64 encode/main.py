#
# Custom base64 encode - Encode selected region with custom base64 table
#
# Copyright (c) 2016, Nobutaka Mantani
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
import string
import subprocess

standard_table = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='

offset = getSelectionOffset()
length = getSelectionLength()
if (length > 0):
    # Do not show command prompt window
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

    # Execute dialog.py to show GUI
    # GUI portion is moved to dialog.py to avoid hangup of FileInsight
    p = subprocess.Popen(["python", "dialog.py"], startupinfo=startupinfo, stdout=subprocess.PIPE)

    # Get base64 table input
    stdout_data, stderr_data = p.communicate()
    custom_table = stdout_data.rstrip()
    custom_table_length = len(custom_table)

    if (custom_table_length > 0):
        if (custom_table_length != 65):
            print "Error: base64 table must be 65 characters (including padding)."
        else:
            data = getSelection()
            orig = list(getDocument())
            orig_len = len(orig)

            trans = string.maketrans(standard_table, custom_table)
            encoded = list(base64.b64encode(data).translate(trans))
            final_size = len(encoded)
            newdata = [0] * (orig_len - (length - final_size))
            
            newdata = orig[:offset]
            newdata.extend(encoded)
            newdata.extend(orig[offset + length:])

            newDocument("New file", 1)
            setDocument("".join(newdata))
            setBookmark(offset, final_size, hex(offset), "#c8ffff")

            if (length == 1):
                print "Encoded one byte with custom base64 table from offset %s to %s." % (hex(offset), hex(offset))
            else:
                print "Encoded %s bytes with custom base64 table from offset %s to %s." % (length, hex(offset), hex(offset + length - 1))

