#
# Binwalk scan - Scan selected region (the whole file if not selected) to find embedded files
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

import collections
import json
import os
import subprocess
import sys

binwalk_path = os.getcwd() + "\\python3-embed\\binwalk.exe"

if not os.path.exists(binwalk_path):
    exit(-1)

file_path = sys.argv[1]
log_path = sys.argv[2]
offset = int(sys.argv[3])

# Do not show command prompt window
startupinfo = subprocess.STARTUPINFO()
startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

# Execute binwalk_scan.py for scanning with binwalk
p = subprocess.Popen([binwalk_path, "-a", "-q", "-l", log_path, file_path], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE)

# Receive scan result
stdout_data, stderr_data = p.communicate()
ret = p.wait()

with open(log_path, "r") as f:
    output = json.load(f, object_pairs_hook=collections.OrderedDict)

for dict in output[0]["Analysis"]["file_map"]:
    description = dict["description"].replace("\n", " ")
    description = description.replace("\r", "")
    print("Offset: 0x%x\t%s" % (offset + dict["offset"], description))
