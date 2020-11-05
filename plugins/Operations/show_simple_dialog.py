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

import sys
import tkinter
import tkinter.simpledialog

# Print input to stdout
def print_input(r, e):
    """
    Prints the input.

    Args:
        r: (str): write your description
        e: (dict): write your description
    """
    print(e.get())
    sys.exit()

# Create input dialog
root = tkinter.Tk()
root.title("Dialog")
root.protocol("WM_DELETE_WINDOW", (lambda r=root: r.quit()))

if len(sys.argv) < 2:
    label = tkinter.Label(root, text="")
else:
    label = tkinter.Label(root, text=sys.argv[1])
label.grid(row=0, column=0, padx=5, pady=5, sticky="w")

entry = tkinter.Entry(root, width=80)
entry.grid(row=1, column=0, padx=5, pady=5, sticky="w")
entry.bind("<Return>", lambda r=root, e=entry: print_input(r, e)) # Event handler for hitting enter key
entry.focus() # Focus to this widget

button = tkinter.Button(root, text='OK', command=(lambda r=root, e=entry: print_input(r, e)))
button.grid(row=2, column=0, padx=5, pady=5, sticky="e")

# Adjust window position
w = root.winfo_screenwidth()
h = root.winfo_screenheight()
root.geometry('+%d+%d' % ((w/2) - 250, (h/2) -100))

root.mainloop()
