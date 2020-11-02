#
# Disassemble - Disassemble selected region (the whole file if not selected)
#
# Copyright (c) 2020, Nobutaka Mantani
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
import os
import sys

try:
    import capstone
except ImportError:
    sys.exit(-1) # Capstone is not installed

file_path = sys.argv[1]
offset = int(sys.argv[2])
arch = int(sys.argv[3])
mode = int(sys.argv[4])

try:
    # Receive data from temporary file
    with open(file_path, "rb") as f:
        data = f.read()

    md = capstone.Cs(arch, mode)
    end = 0
    for i in md.disasm(data, offset):
        s = binascii.b2a_hex(i.bytes).decode().upper()
        code_hex = [s[j: j+2] for j in range(0, len(s), 2)]
        code_hex = " ".join(code_hex)
        print("0x%x:\t%s %s\t(%s)" %(i.address, i.mnemonic, i.op_str, code_hex))
        end = i.address + i.size
except Exception as e:
    print("Error: %s" % e, file=sys.stderr)
    sys.exit(1)

if end < offset + len(data):
    print("%d" % end, file=sys.stderr)

sys.exit(0)
