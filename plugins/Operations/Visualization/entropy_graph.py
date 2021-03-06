#
# Entropy graph - Show entropy graph of selected region (the whole file if not selected)
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
    sys.exit(0) # Do nothing, only checking existence of matplotlib and seaborn

# Receive data from a temporary file
filename = sys.argv[1]
with open(filename, "rb") as f:
    data = f.read()

data = [x for x in data.split(b"\t")]
offset = int(data[0].decode())
blocksize = int(data[1].decode())
data = data[2:]
data = [float(x.decode()) for x in data]

label = []
for i in range(0, len(data)):
    label.append(hex(offset))
    offset += blocksize

matplotlib.pyplot.figure(figsize=(6, 3))
seaborn.set_context("paper", font_scale=0.8)

ax = seaborn.lineplot(data=data)
seaborn.despine()
ax.set_xticks(range(0, len(data)))
ax.set_xticklabels(label, rotation="vertical")

tick_skip = 16
ax.xaxis.set_major_locator(matplotlib.ticker.MultipleLocator(tick_skip))

ax.set_xlabel("Offset")
ax.set_ylabel("Entropy")
ax.set_xlim(0, len(label) - 1)
ax.set_ylim(0, 8)

matplotlib.pyplot.tight_layout()
matplotlib.pyplot.show()

# Remove temporary file on exit
os.remove(filename)
