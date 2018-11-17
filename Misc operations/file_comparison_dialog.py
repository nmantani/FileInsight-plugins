#
# File comparison - Compare contents of two files
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
import time
import Tkinter
import ttk
import tkMessageBox

# Print selected items
def get_selection(r, c1, c2):
    print "%d %d" % (c1.current(), c2.current())
    r.quit()

# Read list of files from stdin
files = sys.stdin.readlines()

# Create input dialog
root = Tkinter.Tk()
root.title("File comparison")
root.protocol("WM_DELETE_WINDOW", (lambda r=root: r.quit()))

label1 = Tkinter.Label(root, text="First file:")
label1.grid(row=0, column=0, padx=5, pady=5)

combo1 = ttk.Combobox(root, state="readonly")
combo1["values"] = files
combo1.current(0)
combo1.grid(row=0, column=2, padx=5, pady=5)

label2 = Tkinter.Label(root, text="Second file:")
label2.grid(row=1, column=0, padx=5, pady=5)

combo2 = ttk.Combobox(root, state="readonly")
combo2["values"] = files
combo2.current(1)
combo2.grid(row=1, column=2, padx=5, pady=5)
combo2
button = Tkinter.Button(root, text="OK", command=(lambda r=root, c1=combo1, c2=combo2: get_selection(r, c1, c2)))
button.grid(row=2, column=0, padx=5, pady=5, columnspan=3)

# Adjust window position
w = root.winfo_screenwidth()
h = root.winfo_screenheight()
root.geometry("+%d+%d" % ((w/2.5), (h/2.5)))

root.mainloop()

