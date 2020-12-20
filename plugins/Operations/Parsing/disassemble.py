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
    address = []
    mnemonic = []
    op_str = []
    code_hex = []
    for i in md.disasm(data, offset):
        s = binascii.b2a_hex(i.bytes).decode().upper()
        code_hex.append(" ".join([s[j: j+2] for j in range(0, len(s), 2)]))
        address.append(i.address)
        mnemonic.append(i.mnemonic)
        op_str.append(i.op_str)
        end = i.address + i.size

    max_len_address = 0
    max_len_mnemonic = 0
    max_len_op_str = 0
    max_len_code_hex = 0
    for i in range(0, len(address)):
        if len("0x%X:" % address[i]) > max_len_address:
            max_len_address = len("0x%X" % address[i])
        if len(mnemonic[i]) > max_len_mnemonic:
            max_len_mnemonic = len(mnemonic[i])
        if len(op_str[i]) > max_len_op_str:
            max_len_op_str = len(op_str[i])
        if len(code_hex[i]) > max_len_code_hex:
            max_len_code_hex = len(code_hex[i])

    for i in range(0, len(address)):
        address[i] = ("0x%X:" % address[i]) + " " * (max_len_address - len("0x%X:" % address[i]))
        mnemonic[i] += " " * (max_len_mnemonic - len(mnemonic[i]))
        op_str[i] += " " * (max_len_op_str - len(op_str[i]))
        code_hex[i] = ("[%s]" % code_hex[i]) + " " * (max_len_code_hex - len(code_hex[i]))
        print("%s\t%s\t%s\t%s" % (address[i], mnemonic[i], op_str[i], code_hex[i]))
except Exception as e:
    print("Error: %s" % e, file=sys.stderr)
    sys.exit(1)

if end < offset + len(data):
    print("%d" % end, file=sys.stderr)

sys.exit(0)
