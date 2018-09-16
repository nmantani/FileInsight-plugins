#
# Compression operations - Various compression / decompression operations to
# selected region
#
# Copyright (c) 2018, Nobutaka Mantani
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

import sys
import Tkinter

operations = ("aPLib compress",
              "aPLib decompress",
              "Bzip2 compress",
              "Bzip2 decompress",
              "Gzip compress",
              "Gzip decompress",
              "LZNT1 compress",
              "LZNT1 decompress",
              "Raw deflate",
              "Raw inflate")
exit_value = -1

root = Tkinter.Tk()
root.bind("<FocusOut>", lambda x:root.quit())

# Adjust menu position
x = int(sys.argv[1])
if x > 10:
    x = x - 10
y = int(sys.argv[2])
if y > 10:
    y = y - 10

# Add menu items
menu1 = Tkinter.Menu(root, tearoff=False)
menu2 = Tkinter.Menu(menu1, tearoff=False)
menu1.add_cascade(label="Compression operations", menu=menu2)

for i in range(0, len(operations)):
    def index(i=i):
        global exit_value
        exit_value = i
        root.quit()

    menu2.add_command(label=operations[i], command=index)

root.withdraw() # Hide root window
menu1.post(x, y) # Show popup menu

root.mainloop()

sys.exit(exit_value)
