#
# XOR operations - Various XOR related operations to selected region
# (the whole file if not selected)
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
import tkinter

operations = ("Decremental XOR",
              "Incremental XOR",
              "Null-preserving XOR",
              "XOR with next byte",
              "Guess 256 byte XOR keys",
              "Visual Decrypt",
              "Visual Encrypt")
exit_value = -1

root = tkinter.Tk()
root.bind("<FocusOut>", lambda x:root.quit())

# Adjust menu position
x = int(sys.argv[1])
if x > 10:
    x = x - 10
y = int(sys.argv[2])
if y > 10:
    y = y - 10

# Add menu items
menu1 = tkinter.Menu(root, tearoff=False)
menu2 = tkinter.Menu(menu1, tearoff=False)
menu1.add_cascade(label="XOR operations", menu=menu2)

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
