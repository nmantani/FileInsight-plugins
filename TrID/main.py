#
# TrID - Send selected region (the whole file if not selected) to TrID
#
# Copyright (c) 2012, Nobutaka Mantani
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

import tempfile
import subprocess
import time
import os

TRID_PATH = "C:\\Program Files\\trid_net\\TrIDNet.exe" # EDIT HERE

length = getSelectionLength()
if (length > 0):
    data = getSelection()
else:
    data = getDocument()

fd, filepath = tempfile.mkstemp()
handle = os.fdopen(fd, "w")
handle.write(data)
handle.close()

subprocess.Popen([TRID_PATH, filepath], shell=False)
time.sleep(3)
os.remove(filepath)

if (length > 0):
    if (length == 1):
        print "Sent one byte from offset %s to %s to TrID." % (hex(offset), hex(offset))
    else:
        print "Sent %s bytes from offset %s to %s to TrID." % (length, hex(offset), hex(offset + length - 1))
else:
    length = getLength()
    if (length == 1):
        print "Sent the whole file (one byte) to TrID."
    else:
        print "Sent the whole file (%s bytes) to TrID." % length

