#
# Replace - Replace matched data in selected region (the whole file if not selected)
# with specified data
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
import tkinter
import tkinter.ttk

# Print selected items
def get_input(r, e1, e2, c):
    """
    Get input

    Args:
        r: (str): write your description
        e1: (todo): write your description
        e2: (todo): write your description
        c: (todo): write your description
    """
    print(e1.get())
    print(e2.get())
    print(c.get())
    r.quit()

# Create input dialog
root = tkinter.Tk()
root.title("Replace")
root.protocol("WM_DELETE_WINDOW", (lambda r=root: r.quit()))

label1 = tkinter.Label(root, text="Search keyword\n(Python regular expression):", justify="left")
label1.grid(row=0, column=0, padx=5, pady=5, columnspan=2, sticky="w")

entry1 = tkinter.Entry(root, width=40)
entry1.grid(row=0, column=2, padx=5, pady=5)

label2 = tkinter.Label(root, text="Replacement:")
label2.grid(row=1, column=0, padx=5, pady=5, sticky="w")

combo = tkinter.ttk.Combobox(root, state="readonly", width=4)
combo["values"] = ["Text", "Hex"]
combo.current(0)
combo.grid(row=1, column=1, padx=5, pady=5)

entry2 = tkinter.Entry(root, width=40)
entry2.grid(row=1, column=2, padx=5, pady=5)

button = tkinter.Button(root, text="OK", command=(lambda r=root, e1=entry1, e2=entry2, c=combo: get_input(r, e1, e2, c)))
button.grid(row=2, column=0, padx=5, pady=5, columnspan=3)

# Adjust window position
w = root.winfo_screenwidth()
h = root.winfo_screenheight()
root.geometry("+%d+%d" % ((w/3), (h/2.5)))

root.mainloop()
