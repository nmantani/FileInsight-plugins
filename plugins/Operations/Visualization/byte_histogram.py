#
# Byte histogram - Show byte histogram of selected region (the whole file if not selected)
#
# Copyright (c) 2021, Nobutaka Mantani
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

import os
import sys

try:
    import matplotlib
except ImportError:
    exit(-1) # matplotlib is not installed

try:
    import seaborn
except ImportError:
    exit(-2) # seaborn is not installed

if sys.argv[1] == "-c":
    sys.exit(0) # Do nothing, only checking existence of seaborn, matplotlib and pandas

# Receive data from a temporary file
filename = sys.argv[1]
with open(filename, "rb") as f:
    file_data = f.read()

# Add empty data to make bars of 0x00 and 0xff easier to see
label = [""] * 2
label += ["0x%02X" % x for x in range(0, 256)]
label += [""] * 2
data = [[0]] * 2
data += [[int(x.decode())] for x in file_data.split(b"\t")]
data += [[0]] * 2

matplotlib.pyplot.figure(figsize=(6, 3))
seaborn.set_context("paper", font_scale=0.8)

ax = seaborn.barplot(data=data)
ax.set_xticklabels(label, rotation="vertical")
ax.set_xticks(range(2, len(label), 16))
ax.set_xlabel("Value")
ax.set_ylabel("Count")

matplotlib.pyplot.tight_layout()
matplotlib.pyplot.show()

# Remove temporary file on exit
os.remove(filename)
