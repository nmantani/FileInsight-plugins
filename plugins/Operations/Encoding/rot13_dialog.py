#
# ROT13 - Rotate alphabet characters in selected region
#
# Copyright (c) 2019, Nobutaka Mantani
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

import re
import tkinter

# Print amount of rotation to stdout
def print_amount(r, s):
    """
    Print the amount of characters

    Args:
        r: (str): write your description
        s: (dict): write your description
    """
    if s.get() != "":
        print(s.get())
    r.quit()

def amount_changed(*args):
    """
    Changes the amount of changed amount.

    Args:
    """
    if not re.match("^-?([0-9])+$", amount.get()):
        amount.set("13")

# Create input dialog
root = tkinter.Tk()
root.title('ROT13')
root.protocol("WM_DELETE_WINDOW", (lambda r=root: r.quit()))
label = tkinter.Label(root, text='Amount of rotation:')
label.grid(row=0, column=0, padx=5, pady=5)
amount = tkinter.StringVar()
amount.set("13")
amount.trace("w", amount_changed)
spin = tkinter.Spinbox(root, textvariable=amount, state="readonly", width=4, from_=-100, to=100)
spin.grid(row=0, column=1, padx=5, pady=5)
button = tkinter.Button(root, text='OK', command=(lambda r=root, s=spin: print_amount(r, s)))
button.grid(row=0, column=2, padx=5, pady=5)

# Adjust window position
w = root.winfo_screenwidth()
h = root.winfo_screenheight()
root.geometry('+%d+%d' % ((w/2.5), (h/2)))

root.mainloop()

