#
# XOR with another file - XOR selected region (the whole file if not selected) while using the content of another file as XOR key
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

import sys
import tkinter
import tkinter.ttk

# Print selected items
def get_selection(r, c1, c2):
    print("%d %d" % (c1.current(), c2.current()))
    root.quit()

# Read list of files from stdin
files = sys.stdin.readlines()

max_len = 0
for f in files:
    if len(f) > max_len:
        max_len = len(f)

# Create input dialog
root = tkinter.Tk()
root.title("XOR with another file")
root.protocol("WM_DELETE_WINDOW", (lambda r=root: r.quit()))

label1 = tkinter.Label(root, text="File to be XORed:")
label1.grid(row=0, column=0, padx=5, pady=5, sticky="w")

combo1 = tkinter.ttk.Combobox(root, state="readonly", width=max_len)
combo1["values"] = files
combo1.current(0)
combo1.grid(row=0, column=1, padx=5, pady=5, sticky="w")

label2 = tkinter.Label(root, text="XOR key file:")
label2.grid(row=1, column=0, padx=5, pady=5, sticky="w")

combo2 = tkinter.ttk.Combobox(root, state="readonly", width=max_len)
combo2["values"] = files
combo2.current(1)
combo2.grid(row=1, column=1, padx=5, pady=5, sticky="w")
combo2

label2 = tkinter.Label(root, text="XOR key file has to contain only XOR key data.")
label2.grid(row=2, column=0, padx=5, pady=5, sticky="w", columnspan=3)

button = tkinter.Button(root, text="OK", command=(lambda r=root, c1=combo1, c2=combo2: get_selection(r, c1, c2)))
button.grid(row=3, column=0, padx=5, pady=5, columnspan=3)
button.focus() # Focus to this widget

# Set callback functions
for x in (combo1, combo2, button):
    x.bind("<Return>", lambda event, r=root, c1=combo1, c2=combo2: get_selection(r, c1, c2))

# Adjust window position
sw = root.winfo_screenwidth()
sh = root.winfo_screenheight()
root.update_idletasks() # Necessary to get width and height of the window
ww = root.winfo_width()
wh = root.winfo_height()
root.geometry('+%d+%d' % ((sw/2) - (ww/2), (sh/2) - (wh/2)))

root.mainloop()